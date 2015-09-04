# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
from collections import deque
from concurrent import futures
from datetime import datetime, timedelta
import functools
import heapq
import logging
import random
import struct
from enum import Enum

import consts
import enc
import mbase32
import node
import peer as mnpeer
import sshtype

log = logging.getLogger(__name__)

class DataCallback(object):
    def notify_version(self, version):
        pass

    def notify_size(self, size):
        pass

    def notify_mime_type(self, value):
        pass

    def notify_data(self, position, data):
        # returns: True to continue, False to abort download.
        pass

    def notify_finished(self, success):
        pass

class BufferingDataCallback(DataCallback):
    def __init__(self):
        self.version = None
        self.size = None
        self.mime_type = None
        self.data = None
        self.position = 0

    def notify_version(self, version):
        self.version = version

    def notify_size(self, size):
        if size > node.MAX_DATA_BLOCK_SIZE:
            self.data = bytearray()
        self.size = size

    def notify_mime_type(self, mime_type):
        self.mime_type = mime_type

    def notify_data(self, position, data):
        if position != self.position:
            raise Exception("Incomplete download.")

        data_len = len(data)

        if log.isEnabledFor(logging.INFO):
            log.info("Received data; position=[{}], len=[{}]."\
                .format(position, data_len))

        if self.data is None:
            self.data = data
        else:
            self.data += data

        self.position += data_len

        return True

class KeyCallback(object):
    def notify_key(self, key):
        pass

    def notify_referred_key(self, key):
        "This gets called when a link is requested to be stored, the link"
        " is returned with notify_key(..) and the linked key is returned"
        " via this call, notify_referred_key(..)."
        pass

class BlockType(Enum):
    hash_tree = 0x2D4100
    link = 0x2D4200
    targeted = 0x2D4300
    user = 0x80000000

class MorphisBlock(object):
    UUID = b'\x86\xa0\x47\x79\xc1\x2e\x4f\x48\x90\xc3\xee\x27\x53\x6d\x26\x96'
    HEADER_BYTES = 31

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

        i += 7 # MORPHiS

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

        assert consts.NODE_ID_BYTES == HashTreeBlock.HEADER_BYTES
        nbuf += b' ' * (consts.NODE_ID_BYTES - len(nbuf))

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

        i, self.mime_type = sshtype.parse_string_from(self.buf, i)
        self.destination = self.buf[i:]

class TargetedBlock(MorphisBlock):
    NOONCE_OFFSET = MorphisBlock.HEADER_BYTES
    NOONCE_SIZE = 64 #FIXME: This was suppose to be 64 bits, not bytes.
    BLOCK_OFFSET = MorphisBlock.HEADER_BYTES + NOONCE_SIZE\
        + 2 * consts.NODE_ID_BYTES

    @staticmethod
    def set_nonce(data, nonce_bytes):
        assert type(nonce_bytes) in (bytes, bytearray)
        lenn = len(nonce_bytes)
        end = TargetedBlock.NOONCE_OFFSET + TargetedBlock.NOONCE_SIZE
        start = end - lenn
        data[start:end] = nonce_bytes

    def __init__(self, buf=None):
        self.nonce = b' ' * TargetedBlock.NOONCE_SIZE
        self.target_key = None
        self.block_hash = None
        self.block = None

        super().__init__(BlockType.targeted.value, buf)

    def encode(self):
        nbuf = super().encode()

        assert len(self.nonce) == TargetedBlock.NOONCE_SIZE
        nbuf += self.nonce
        assert self.target_key is not None\
            and len(self.target_key) == consts.NODE_ID_BYTES
        nbuf += self.target_key

        nbuf += b' ' * consts.NODE_ID_BYTES # block_hash placeholder.

        assert len(nbuf) == TargetedBlock.BLOCK_OFFSET

        self.block.encode(nbuf)

        self.block_hash = enc.generate_ID(nbuf[TargetedBlock.BLOCK_OFFSET:])
        block_hash_offset = TargetedBlock.BLOCK_OFFSET-consts.NODE_ID_BYTES
        nbuf[block_hash_offset:TargetedBlock.BLOCK_OFFSET] = self.block_hash

        return nbuf

    def parse(self):
        i = super().parse()

        self.nonce = self.buf[i:i+TargetedBlock.NOONCE_SIZE]
        i += TargetedBlock.NOONCE_SIZE
        self.target_key = self.buf[i:i+consts.NODE_ID_BYTES]
        i += consts.NODE_ID_BYTES
        self.block_hash = self.buf[i:i+consts.NODE_ID_BYTES]
        i += consts.NODE_ID_BYTES

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
        self._failed = deque()
        self._ordered_waiters = []
        self._ordered_waiters_dc = {} #FIXME: WTF is this?

        self._task_cnt = 0
        self._tasks_done = asyncio.Event()

        self._abort = False

    @asyncio.coroutine
    def fetch(self, root_block):
        self.data_callback.notify_size(root_block.size)

        depth = root_block.depth
        buf = root_block.buf

        i = HashTreeBlock.HEADER_BYTES

        yield from self._fetch_hash_tree_refs(buf, i, depth, 0)

        if self._abort:
            return False

        yield from self._tasks_done.wait()

        if self._abort:
            return False

        if self._failed:
            max_delta = timedelta(seconds=self.retry_seconds)

            last_fail_count = 0

            while True:
                current_fail_count = len(self._failed)

                if not current_fail_count:
                    break

                if current_fail_count != last_fail_count:
                    start = datetime.today()
                    last_fail_count = current_fail_count

                if (datetime.today() - start) > max_delta:
                    break

                yield from self._task_semaphore.acquire()
                if self._abort:
                    return False
                self._schedule_retry()

            yield from self._tasks_done.wait()

            if self._failed or self._abort:
                return False

        return True

    @asyncio.coroutine
    def _fetch_hash_tree_refs(self, hash_tree_data, offset, depth, position):
        data_len = len(hash_tree_data) - offset

        key_cnt = int(data_len / consts.NODE_ID_BYTES)

        if depth == 1:
            pdiff = consts.MAX_DATA_BLOCK_SIZE
        else:
            pdiff =\
                pow(consts.MAX_DATA_BLOCK_SIZE, depth) / consts.NODE_ID_BYTES

        subdepth = depth - 1

        for i in range(key_cnt):
            end = offset + consts.NODE_ID_BYTES
            eposition = position + pdiff

            if self.positions:
                if not self.__need_range(position, eposition):
                    offset = end
                    position = eposition
                    continue

            if self._failed:
                yield from self._task_semaphore.acquire()
                if self._abort:
                    #FIXME: Cancel all async started tasks.
                    return
                self._schedule_retry()

            yield from self._task_semaphore.acquire()
            if self._abort:
                #FIXME: Cancel all async started tasks.
                return

            data_key = hash_tree_data[offset:end]
            asyncio.async(\
                self.__fetch_hash_tree_ref(data_key, subdepth, position),\
                loop=self.engine.loop)

            self._task_cnt += 1
            self._tasks_done.clear()

            offset = end
            position = eposition

    def _schedule_retry(self):
        retry = self._failed.popleft()

        retry_depth, retry_position, data_key, tries = retry

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
        if not retry:
            data_rw = yield from self.engine.tasks.send_get_data(data_key)
        else:
            data_rw = yield from self.engine.tasks.send_get_data(\
                data_key, retry_factor=retry[3] * 10)

        self._task_semaphore.release()

        if self._abort:
            return

        if not data_rw.data:
            # Fetch failed.
            if retry:
                retry[3] += 1 # Tries.

                if retry[3] >= 32:
                    if log.isEnabledFor(logging.INFO):
                        log.info("Block id [{}] failed too much; aborting."\
                            .format(mbase32.encode(data_key)))
                    self._do_abort()
                    return
            else:
                retry = [depth, position, data_key, 1]

            self._failed.append(retry)

            if log.isEnabledFor(logging.INFO):
                log.info("Block id [{}] failed, retrying (tries=[{}])."\
                    .format(mbase32.encode(data_key), retry[3]))

            if self.ordered:
                # This very fetch is probably blocking future ones so retry
                # immediately!
                self._schedule_retry()
        else:
            if retry:
                if log.isEnabledFor(logging.INFO):
                    log.info("Succeeded with retry [{}] on try [{}]."\
                        .format(mbase32.encode(data_key), retry[3]))

            if self.ordered:
                if position != self._next_position:
                    waiter = asyncio.futures.Future(loop=self.engine.loop)
                    yield from self.__wait(position, waiter)

            if not depth:
                r = self.data_callback.notify_data(position, data_rw.data)
                if not r:
                    if log.isEnabledFor(logging.DEBUG):
                        log.debug("Received cancel signal; aborting download.")
                    self._do_abort()
                    return
                self.__notify_position_complete(position + len(data_rw.data))
            else:
                yield from\
                    self._fetch_hash_tree_refs(\
                        data_rw.data, 0, depth, position)

        self._task_cnt -= 1
        if self._task_cnt <= 0:
            assert self._task_cnt == 0
            self._tasks_done.set()

    def _do_abort(self):
        if self._abort:
            return

        self._abort = True
        self._task_semaphore.release()
        self._tasks_done.set()
        for position, waiter in self._ordered_waiters:
            waiter.cancel()

    @asyncio.coroutine
    def __wait(self, position, waiter):
        entry = [position, waiter]

        r = self._ordered_waiters_dc.setdefault(position, entry)
        assert r is entry

        heapq.heappush(self._ordered_waiters, entry)

        yield from waiter

    def __notify_position_complete(self, next_position):
        self._next_position = next_position

        while self._ordered_waiters:
            while self._ordered_waiters:
                position, waiter = self._ordered_waiters[0]
                if position > next_position:
                    return
                waiter.set_result(False)
                heapq.heappop(self._ordered_waiters)
                break

## Functions:

@asyncio.coroutine
def get_data_buffered(engine, data_key, path=None, retry_seconds=30,\
        concurrency=64, max_link_depth=1):
    cb = BufferingDataCallback()

    r = yield from get_data(engine, data_key, cb, path=path, ordered=True,\
            retry_seconds=retry_seconds, concurrency=concurrency,\
            max_link_depth=max_link_depth)

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
        log.info("Download complete; len=[{}].".format(len(cb.data)))

    return cb

@asyncio.coroutine
def get_data(engine, data_key, data_callback, path=None, ordered=False,\
        positions=None, retry_seconds=30, concurrency=64, max_link_depth=1):
    assert not path or type(path) is bytes, type(path)
    assert isinstance(data_callback, DataCallback), type(data_callback)

    data_rw = yield from engine.tasks.send_get_data(data_key, path)
    data = data_rw.data

    if data is None:
        data_rw = yield from engine.tasks.send_get_data(\
            data_key, path, retry_factor=10)
        data = data_rw.data

        if data is None:
            return None

    if data_rw.version:
        data_callback.notify_version(data_rw.version)
    else:
        #FIXME: Remove this from here after it is integrated into the coming
        # chord_task rewrite.
        # Reupload the key to keep prefix searches in the network.
        r = random.randint(1, 5)
        if r == 1:
            asyncio.async(\
                engine.tasks.send_store_key(\
                    data_rw.data, data_key, retry_factor=50),\
                loop=engine.loop)

    link_depth = 0

    while True:
        if not data.startswith(MorphisBlock.UUID):
            data_callback.notify_size(len(data))
            data_callback.notify_data(0, data)
            data_callback.notify_finished(True)
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
                data_callback.notify_mime_type(block.mime_type)

            data_rw = yield from engine.tasks.send_get_data(block.destination)
            data = data_rw.data

            if data is None:
                data_rw = yield from engine.tasks.send_get_data(\
                    block.destination, retry_factor=10)
                data = data_rw.data

                if data is None:
                    return None

            continue

        if block_type != BlockType.hash_tree.value:
            data_callback.notify_size(len(data))
            data_callback.notify_data(0, data)
            data_callback.notify_finished(True)
            return True

        fetch = HashTreeFetch(\
            engine, data_callback, ordered, positions, retry_seconds,\
                concurrency)

        r = yield from fetch.fetch(HashTreeBlock(data))

        data_callback.notify_finished(r)

        return r

@asyncio.coroutine
def store_data(engine, data, privatekey=None, path=None, version=None,\
        key_callback=None, store_key=True, mime_type="", concurrency=64):
    data_len = len(data)

    if isinstance(key_callback, KeyCallback):
        key_callback_obj = key_callback
        key_callback = key_callback_obj.notify_key
    else:
        key_callback_obj = None

    if mime_type or (privatekey and data_len > consts.MAX_DATA_BLOCK_SIZE):
        store_link = True

        root_block_key = None

        orig_key_callback = key_callback
        def key_callback(key):
            nonlocal root_block_key
            root_block_key = key
            if key_callback_obj:
                key_callback_obj.notify_referred_key(key)
    else:
        store_link = False

    if data_len <= consts.MAX_DATA_BLOCK_SIZE:
        if log.isEnabledFor(logging.INFO):
            log.info("Data fits in one block, performing simple store.")

        if privatekey and not store_link:
            yield from engine.tasks.send_store_updateable_key(\
                data, privatekey, path, version, store_key, key_callback)
        else:
            yield from\
                engine.tasks.send_store_data(data, store_key=store_key,\
                    key_callback=key_callback)

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
                link_data, privatekey, path, version, store_key,\
                orig_key_callback)
        else:
            yield from\
                engine.tasks.send_store_data(\
                    link_data, store_key=store_key,\
                    key_callback=orig_key_callback)

        log.info("Link stored.")

def __key_callback(keys, idx, key):
    key_len = len(key)
    assert key_len == consts.NODE_ID_BYTES
    idx = key_len * idx
    keys[idx:idx+key_len] = key

@asyncio.coroutine
def _store_data_multipart(engine, data, key_callback, store_key, concurrency):
    depth = 1
    task_semaphore = asyncio.Semaphore(concurrency)

    full_data_len = data_len = len(data)
    assert data_len > consts.MAX_DATA_BLOCK_SIZE

    while True:
        nblocks = int(data_len / consts.MAX_DATA_BLOCK_SIZE)
        if data_len % consts.MAX_DATA_BLOCK_SIZE:
            nblocks += 1

        keys = bytearray(nblocks * consts.NODE_ID_BYTES)

        start = 0
        end = consts.MAX_DATA_BLOCK_SIZE

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
            end += consts.MAX_DATA_BLOCK_SIZE
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
                <= (consts.MAX_DATA_BLOCK_SIZE - HashTreeBlock.HEADER_BYTES):
            break

        depth += 1

    # Store root MorphisBlock.
    block = HashTreeBlock()
    block.depth = depth
    block.size = full_data_len
    block.data = keys

    block_data = block.encode()

#    yield from\
#        engine.tasks.send_store_data(block_data, store_key=store_key,\
#            key_callback=key_callback, retry_factor=50)
    yield from\
        _store_block(\
            engine, -1, block_data, key_callback, task_semaphore,\
            store_key=store_key)

@asyncio.coroutine
def _store_block(engine, i, block_data, key_callback, task_semaphore,\
        store_key=False):
    tries = 0
    storing_nodes = 0

    while True:
        if not tries:
            snodes = yield from\
                engine.tasks.send_store_data(\
                    block_data, store_key=store_key, key_callback=key_callback)
        else:
            if store_key:
                if tries > 1:
                    store_key = False

            snodes = yield from\
                engine.tasks.send_store_data(\
                    block_data, store_key=store_key,\
                    key_callback=key_callback,\
                    retry_factor=tries * 10)

        task_semaphore.release()

        storing_nodes += snodes

        if storing_nodes >= 3:
            return True
        else:
            if log.isEnabledFor(logging.INFO):
                log.info("Only stored block #{} to [{}] nodes so far;"\
                    " trying again (tries=[{}])."\
                        .format(i, storing_nodes, tries))

        if tries == 1:
            # Grab the data_key this time for use on next try's logic below.
            data_key = None
            orig_key_callback = key_callback
            def key_callback(key):
                nonlocal data_key, key_callback
                data_key = key
                orig_key_callback(key)
                key_callback = orig_key_callback
        elif tries == 2:
            data_rw =\
                yield from\
                    engine.tasks.send_get_data(data_key, retry_factor=30,\
                        scan_only=True)
            if data_rw.data is not None and data_rw.data_present_cnt:
                storing_nodes += data_rw.data_present_cnt
                if log.isEnabledFor(logging.INFO):
                    log.info("Block #{} was found [{}] times on the network."\
                        .format(i, data_rw.data_present_cnt))
                if storing_nodes >= 3:
                    if log.isEnabledFor(logging.INFO):
                        log.info("Block #{} is already redundant enough on"\
                            " the network; not uploading it anymore for now."\
                                .format(i))
                    return True

        tries += 1

        if tries < 5:
#            yield from asyncio.sleep(1.1**1.1**tries)
            yield from task_semaphore.acquire()
            continue

        if log.isEnabledFor(logging.WARNING):
            log.warn("Failed to upload block #{} enough (storing_nodes=[{}])."\
                .format(i, storing_nodes))

        return False
