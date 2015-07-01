import llog

import asyncio
from concurrent import futures
import functools
import heapq
import logging
import random
import struct
from enum import Enum

import chord
from mutil import hex_string
import node as mnnode
import peer as mnpeer
import sshtype

log = logging.getLogger(__name__)

@asyncio.coroutine
def get_data(engine, data_key, data_callback, ordered=False, positions=None,\
        concurrency=64):
    data_rw = yield from engine.tasks.send_get_data(data_key)

    data = data_rw.data

    if not data:
        return None

    if not data.startswith(MorphisBlock.UUID):
        return data
    if MorphisBlock.parse_block_type(data) != BlockType.hash_tree.value:
        return data

    fetch = HashTreeFetch(engine, ordered, concurrency)
    fetch.get(HashTreeBlock(data, positions, data_callback))

class HashTreeFetch(object):
    def __init__(self, engine, data_callback, ordered=False, positions=None,\
            concurrency=64):
        self.engine = engine
        self.data_callback = data_callback
        self.ordered = ordered
        self.positions = positions
        self.concurrency = concurrency

        self._task_semaphore = asyncio.Semaphore(concurrency)
        self._next_position = 0
        self._failed = []

    @asyncio.coroutine
    def fetch(self, root_block):
        depth = root_block.depth
        buf = root_block.buf

        i = HashTreeBlock.HEADER_BYTES

        yield from\
            self._fetch_hash_tree_refs(buf, i, depth, 0)

    @asyncio.coroutine
    def _fetch_hash_tree_refs(self, hash_tree_data, offset, depth, position):
        data_len = len(hash_tree_data) - offset

        key_cnt = data_len / chord.NODE_ID_BYTES

        if depth == 1:
            pdiff = mnnode.MAX_DATA_BLOCK_SIZE
        else:
            pdiff =\
                pow(mnnode.MAX_DATA_BLOCK_SIZE, depth) / mnnode.NODE_ID_BYTES

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
                retry = random.choice(self._failed)

                data_key = retry.data_key
                yield from self._task_semaphore.acquire()

                asyncio.async(\
                    self.__fetch_hash_tree_ref(\
                        data_key, retry.depth, retry.position, retry),\
                    loop=self.engine.loop)

            data_key = hash_tree_data[offset:end]

            yield from self._task_semaphore.acquire()

            asyncio.async(\
                self.__fetch_hash_tree_ref(data_key, subdepth, position),\
                loop=self.engine.loop)

            offset = end
            position = eposition

    def __need_range(self, start, end):
        #TODO: YOU_ARE_HERE: Check if overlap with self.positions.
        raise Exception("Not Implemented!")

    @asyncio.coroutine
    def __fetch_hash_tree_ref(self, data_key, depth, position, retry=None):
        data_rw = yield from self.engine.tasks.send_get_data(data_key)

        self._task_semaphore.release()

        if not data_rw.data:
            if retry:
                return

            self._failed += {\
                depth: depth,
                position: position,
                data_key: data_key}
            return
        else:
            if retry:
                del self._failed[retry]

        if self.ordered:
            if position != self._next_position:
                waiter = asyncio.futures.Future(loop=self.engine.loop)
                yield from self.__wait(position, waiter)

        if not depth:
            self.data_callback(position, data_rw.data)
            self.__notify_position_complete(position + len(data_rw.data))
        else:
            yield from\
                self._fetch_hash_tree_refs(data_rw.data, 0, depth, position)

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

@asyncio.coroutine
def store_data(engine, data, privatekey=None, path=None, version=None,\
        key_callback=None, store_key=True, concurrency=64):

    data_len = len(data)

    if data_len <= mnnode.MAX_DATA_BLOCK_SIZE:
        if log.isEnabledFor(logging.INFO):
            log.info("Data fits in one block, performing simple store.")

        if privatekey:
            yield from engine.tasks.send_store_updateable_key(\
                data, privatekey, path, version, key_callback)

            if store_key:
                yield from engine.tasks.send_store_updateable_key_key(\
                    data, privatekey, path, key_callback)
        else:
            yield from engine.tasks.send_store_data(data, key_callback)

            if store_key:
                yield from engine.tasks.send_store_key(data)

        if log.isEnabledFor(logging.INFO):
            log.info("Simple store complete.")

        return

    if log.isEnabledFor(logging.INFO):
        log.info("Storing multipart.")

    yield from _store_data(engine, data, key_callback, store_key, concurrency)

def __key_callback(keys, idx, key):
    key_len = len(key)
    assert key_len == chord.NODE_ID_BYTES
    idx = key_len * idx
    keys[idx:idx+key_len] = key

@asyncio.coroutine
def _store_data(engine, data, key_callback, store_key, concurrency):
    depth = 1
    task_semaphore = asyncio.Semaphore(concurrency)

    data_len = len(data)
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

class BlockType(Enum):
    hash_tree = 0
    user = 1

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

        self.user_type = struct.unpack_from(">L", self.buf, i)[0]
        i += 4

        return i

class HashTreeBlock(MorphisBlock):
    HEADER_BYTES = 64

    def __init__(self, buf=None):
        self.depth = 0
        self.data = None

        super().__init__(BlockType.hash_tree.value, buf)

    def encode(self):
        nbuf = super().encode()
        nbuf += struct.pack(">L", self.depth)

        nbuf += b' ' * (chord.NODE_ID_BYTES - len(nbuf))

        nbuf += self.data

        return nbuf

    def parse(self):
        i = super().parse()

        self.depth = struct.unpack_from(">L", self.buf, i)
