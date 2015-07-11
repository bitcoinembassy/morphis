import llog

import asyncio
from concurrent import futures
from datetime import datetime, timedelta
import functools
import heapq
import logging
import random
import struct
from enum import Enum

import chord
import mbase32
from mutil import hex_string
import node as mnnode
import peer as mnpeer
import sshtype

log = logging.getLogger(__name__)

class DataCallback(object):
    def version(self, version):
        pass

    def size(self, size):
        pass

    def mime_type(self, value):
        pass

    def data(self, position, data):
        pass

class BufferingDataCallback(DataCallback):
    def __init__(self):
        self.version = None
        self.buf = bytearray()
        self.position = 0

    def version(self, version):
        self.version = version

    def data(self, position, data):
        if position != self.position:
            raise Exception("Incomplete download.")

        data_len = len(data)

        if log.isEnabledFor(logging.INFO):
            log.info("Received data; position=[{}], len=[{}]."\
                .format(position, data_len))

        self.buf += data
        self.position += data_len

class BlockType(Enum):
    hash_tree = 0x2D4100
    link = 0x2D4200
    targeted = 0x2D4300
    user = 0x80000000

class MorphisBlock(object):
    UUID = b'\x86\xa0\x47\x79\xc1\x2e\x4f\x48\x90\xc3\xee\x27\x53\x6d\x26\x96'

    @staticmethod
    def parse_block_type(buf):
        return struct.unpack_from(">L", buf, 16 + 7)[0]

    def __init__(self, block_type=None, buf=None):
        self.buf = buf
        self.block_type = block_type
        self.ext_type = 0

        if not buf:
            return

        self.parse()

    def encode(self):
        nbuf = bytearray()

        nbuf += MorphisBlock.UUID
        nbuf += b"MORPHiS"
        nbuf += struct.pack(">L", self.block_type)
        nbuf += struct.pack(">L", self.ext_type)

        self.buf = nbuf

        return nbuf

    def parse(self):
        assert self.buf[:16] == MorphisBlock.UUID
        i = 16

        i += 7 # morphis

        block_type = struct.unpack_from(">L", self.buf, i)[0]
        if self.block_type:
            if block_type != self.block_type:
                raise Exception("Expecting block_type [{}] but got [{}]."\
                    .format(self.block_type, block_type))
        self.block_type = block_type
        i += 4

        self.ext_type = struct.unpack_from(">L", self.buf, i)[0]
        i += 4

        return i

class HashTreeBlock(MorphisBlock):
    HEADER_BYTES = 64

    def __init__(self, buf=None):
        self.depth = 0
        self.size = 0
        self.data = None

        super().__init__(BlockType.hash_tree.value, buf)

    def encode(self):
        nbuf = super().encode()
        nbuf += struct.pack(">L", self.depth)
        nbuf += struct.pack(">Q", self.size)

        nbuf += b' ' * (chord.NODE_ID_BYTES - len(nbuf))

        nbuf += self.data

        return nbuf

    def parse(self):
        i = super().parse()

        self.depth = struct.unpack_from(">L", self.buf, i)[0]
        i += 4
        self.size = struct.unpack_from(">Q", self.buf, i)[0]

class LinkBlock(MorphisBlock):
    def __init__(self, buf=None):
        self.mime_type = None
        self.destination = None

        super().__init__(BlockType.link.value, buf)

    def encode(self):
        nbuf = super().encode()
        nbuf += sshtype.encodeString(self.mime_type)
        nbuf += self.destination

        return nbuf

    def parse(self):
        i = super().parse()

        l, self.mime_type = sshtype.parse_string_from(self.buf, i)
        i += l
        self.destination = self.buf[i:]

class HashTreeFetch(object):
    def __init__(self, engine, data_callback, ordered=False, positions=None,\
            retry_seconds=30, concurrency=64):
        self.engine = engine
        self.data_callback = data_callback
        self.ordered = ordered
        self.positions = positions
        self.retry_seconds = retry_seconds
        self.concurrency = concurrency

        self._task_semaphore = asyncio.Semaphore(concurrency)
        self._next_position = 0
        self._failed = []
        self._ordered_waiters = []
        self._ordered_waiters_dc = {}

        self._task_cnt = 0
        self._tasks_done = asyncio.Event()

    @asyncio.coroutine
    def fetch(self, root_block):
        self.data_callback.size(root_block.size)

        depth = root_block.depth
        buf = root_block.buf

        i = HashTreeBlock.HEADER_BYTES

        yield from self._fetch_hash_tree_refs(buf, i, depth, 0)

        yield from self._tasks_done.wait()

        if self._failed:
            delta = timedelta(seconds=self.retry_seconds)
            start = datetime.today()

            while self._failed\
                    and ((datetime.today() - start) < delta):
                yield from self._task_semaphore.acquire()
                self._schedule_retry()

            yield from self._tasks_done.wait()

            if self._failed:
                return False

        return True

    @asyncio.coroutine
    def _fetch_hash_tree_refs(self, hash_tree_data, offset, depth, position):
        data_len = len(hash_tree_data) - offset

        key_cnt = int(data_len / chord.NODE_ID_BYTES)

        if depth == 1:
            pdiff = mnnode.MAX_DATA_BLOCK_SIZE
        else:
            pdiff =\
                pow(mnnode.MAX_DATA_BLOCK_SIZE, depth) / chord.NODE_ID_BYTES

        subdepth = depth - 1

        for i in range(key_cnt):
            end = offset + chord.NODE_ID_BYTES
            eposition = position + pdiff

            if self.positions:
                if not self.__need_range(position, eposition):
                    offset = end
                    position = eposition
                    continue

            if self._failed:
                yield from self._task_semaphore.acquire()
                self._schedule_retry()

            yield from self._task_semaphore.acquire()
            data_key = hash_tree_data[offset:end]
            asyncio.async(\
                self.__fetch_hash_tree_ref(data_key, subdepth, position),\
                loop=self.engine.loop)

            self._task_cnt += 1
            self._tasks_done.clear()

            offset = end
            position = eposition

    def _schedule_retry(self):
        retry = random.choice(self._failed)
        retry_depth, retry_position, data_key = retry

        asyncio.async(\
            self.__fetch_hash_tree_ref(\
                data_key, retry_depth, retry_position, retry),\
            loop=self.engine.loop)

        self._task_cnt += 1
        self._tasks_done.clear()

    def __need_range(self, start, end):
        #TODO: YOU_ARE_HERE: Check if overlap with self.positions.
        raise Exception("Not Implemented!")

    @asyncio.coroutine
    def __fetch_hash_tree_ref(self, data_key, depth, position, retry=None):
        data_rw = yield from self.engine.tasks.send_get_data(data_key)

        self._task_semaphore.release()

        if not data_rw.data:
            if not retry:
                self._failed.append((depth, position, data_key))
        else:
            if retry:
                del self._failed[retry]

            if self.ordered:
                if position != self._next_position:
                    waiter = asyncio.futures.Future(loop=self.engine.loop)
                    yield from self.__wait(position, waiter)

            if not depth:
                self.data_callback.data(position, data_rw.data)
                self.__notify_position_complete(position + len(data_rw.data))
            else:
                yield from\
                    self._fetch_hash_tree_refs(\
                        data_rw.data, 0, depth, position)

        self._task_cnt -= 1
        if self._task_cnt <= 0:
            assert self._task_cnt == 0
            self._tasks_done.set()

    def __wait(self, position, waiter):
        entry = [position, waiter]

        r = self._ordered_waiters_dc.setdefault(position, entry)
        assert r is entry

        heapq.heappush(self._ordered_waiters, entry)

        yield from waiter

    def __notify_position_complete(self, next_position):
        self._next_position = next_position

        while self._ordered_waiters:
            position, waiter = self._ordered_waiters[0]
            if position > next_position:
                return
            waiter.set_result(False)
            heapq.heappop(self._ordered_waiters)

## Functions:

@asyncio.coroutine
def get_data_buffered(engine, data_key, path=None, retry_seconds=30,\
        concurrency=64, max_link_depth=1):
    cb = BufferingDataCallback()

    r = yield from get_data(engine, data_key, path, cb, ordered=True,\
            retry_seconds=retry_seconds, concurrency=concurrency)

    if not r:
        if r is None:
            if log.isEnabledFor(logging.INFO):
                log.info("Key not found.")
            return None, None
        else:
            if log.isEnabledFor(logging.INFO):
                log.info("Download timed out.")
            return False, None

    if log.isEnabledFor(logging.INFO):
        log.info("Download complete; len=[{}].".format(len(cb.buf)))

    return cb.buf, cb.version

@asyncio.coroutine
def get_data(engine, data_key, data_callback, path=None, ordered=False,\
        positions=None, retry_seconds=30, concurrency=64, max_link_depth=1):
    assert not path or type(path) is bytes, type(path)
    assert isinstance(data_callback, DataCallback), type(data_callback)

    data_rw = yield from engine.tasks.send_get_data(data_key, path)
    data = data_rw.data

    if not data:
        return None

    if data_rw.version:
        data_callback.version(data_rw.version)

    link_depth = 0

    while True:
        if not data.startswith(MorphisBlock.UUID):
            data_callback.size(len(data))
            data_callback.data(0, data)
            return True

        block_type = MorphisBlock.parse_block_type(data)

        if block_type == BlockType.link.value:
            link_depth += 1

            if link_depth > max_link_depth:
                if log.isEnabledFor(logging.WARNING):
                    log.warning(\
                        "Exceeded maximum link depth [{}] for key [{}]."\
                            .format(max_link_depth, mbase32.encode(data_key)))
                return False

            block = LinkBlock(data)

            if block.mime_type:
                data_callback.mime_type(block.mime_type)

            data_rw = yield from engine.tasks.send_get_data(block.destination)
            data = data_rw.data

            if not data:
                return None

            continue

        if block_type != BlockType.hash_tree.value:
            data_callback.size(len(data))
            data_callback.data(0, data)
            return True

        fetch = HashTreeFetch(\
            engine, data_callback, ordered, positions, retry_seconds,\
                concurrency)

        r = yield from fetch.fetch(HashTreeBlock(data))

        return r

@asyncio.coroutine
def store_data(engine, data, privatekey=None, path=None, version=None,\
        key_callback=None, store_key=True, mime_type="", concurrency=64):
    data_len = len(data)

    if mime_type or (privatekey and data_len > mnnode.MAX_DATA_BLOCK_SIZE):
        store_link = True

        root_block_key = None

        orig_key_callback = key_callback
        def key_callback(key):
            nonlocal root_block_key
            root_block_key = key
    else:
        store_link = False

    if data_len <= mnnode.MAX_DATA_BLOCK_SIZE:
        if log.isEnabledFor(logging.INFO):
            log.info("Data fits in one block, performing simple store.")

        if privatekey and not store_link:
            yield from engine.tasks.send_store_updateable_key(\
                data, privatekey, path, version, key_callback)

            if store_key:
                yield from engine.tasks.send_store_updateable_key_key(\
                    data, privatekey, path)
        else:
            yield from engine.tasks.send_store_data(data, key_callback)

            if store_key:
                yield from engine.tasks.send_store_key(data)

        if log.isEnabledFor(logging.INFO):
            log.info("Simple store complete.")
    else:
        if log.isEnabledFor(logging.INFO):
            log.info("Storing multipart.")

        yield from _store_data_multipart(\
                engine, data, key_callback, store_key, concurrency)

        log.info("Multipart storage complete.")

    if store_link:
        log.info("Storing link.")

        block = LinkBlock()
        block.mime_type = mime_type
        block.destination = root_block_key
        link_data = block.encode()

        if privatekey:
            yield from engine.tasks.send_store_updateable_key(\
                link_data, privatekey, path, version, orig_key_callback)

            if store_key:
                yield from\
                    engine.tasks.send_store_updateable_key_key(privatekey)
        else:
            yield from\
                engine.tasks.send_store_data(link_data, orig_key_callback)

            if store_key:
                yield from engine.tasks.send_store_key(link_data)

        log.info("Link stored.")

def __key_callback(keys, idx, key):
    key_len = len(key)
    assert key_len == chord.NODE_ID_BYTES
    idx = key_len * idx
    keys[idx:idx+key_len] = key

@asyncio.coroutine
def _store_data_multipart(engine, data, key_callback, store_key, concurrency):
    depth = 1
    task_semaphore = asyncio.Semaphore(concurrency)

    full_data_len = data_len = len(data)
    assert data_len > mnnode.MAX_DATA_BLOCK_SIZE

    while True:
        nblocks = int(data_len / mnnode.MAX_DATA_BLOCK_SIZE)
        if data_len % mnnode.MAX_DATA_BLOCK_SIZE:
            nblocks += 1

        keys = bytearray(nblocks * chord.NODE_ID_BYTES)

        start = 0
        end = mnnode.MAX_DATA_BLOCK_SIZE

        tasks = []

        for i in range(nblocks):
            _key_callback = functools.partial(__key_callback, keys, i)

            tasks.append(\
                asyncio.async(\
                    _store_block(\
                        engine, i, data[start:end], _key_callback,\
                        task_semaphore),\
                    loop=engine.loop))

            if task_semaphore.locked():
                done, pending = yield from asyncio.wait(tasks,\
                    loop=engine.loop, return_when=futures.FIRST_COMPLETED)
                tasks = list(pending)

#                for task in done:
#                    if not task.result():
#                        log.warning("Upload failed!")
#                        return False

            yield from task_semaphore.acquire()

            start = end
            end += mnnode.MAX_DATA_BLOCK_SIZE
            if end > data_len:
                assert i >= (nblocks - 2)
                end = data_len

        # Wait for all previous hashes to be done. This simplifies the code, as
        # otherwise we have to track which are done to make sure we are not
        # uploading a block of hashes that is not complete.
        done, pending = yield from asyncio.wait(tasks, loop=engine.loop)
        tasks = list()

        data = keys
        data_len = len(data)
        if data_len\
                <= (mnnode.MAX_DATA_BLOCK_SIZE - HashTreeBlock.HEADER_BYTES):
            break

        depth += 1

    # Store root MorphisBlock.
    block = HashTreeBlock()
    block.depth = depth
    block.size = full_data_len
    block.data = keys

    block_data = block.encode()

    yield from\
        engine.tasks.send_store_data(block_data, key_callback)

    if store_key:
        yield from\
            engine.tasks.send_store_key(block_data)

@asyncio.coroutine
def _store_block(engine, i, block_data, key_callback, task_semaphore):
    snodes = yield from engine.tasks.send_store_data(block_data, key_callback)

    if not snodes:
        if log.isEnabledFor(logging.DEBUG):
            log.debug("Failed to upload block #{}.".format(i))

    task_semaphore.release()

    return True
