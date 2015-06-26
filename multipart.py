import llog

import asyncio
from concurrent import futures
import functools
import logging
import struct
from enum import Enum

import chord
from mutil import hex_string
import node as mnnode
import peer as mnpeer
import sshtype

log = logging.getLogger(__name__)

@asyncio.coroutine
def get_data(engine, data_key, significant_bits=None, concurrency=64):
    if significant_bits:
        data_rw = yield from\
            engine.tasks.send_find_key(data_key, significant_bits)

        data_key = data_rw.data_key

        if not data_key:
            return None

    data_rw = yield from engine.tasks.send_get_data(data_key)

    data = data_rw.data

    if not data:
        return None

    if not data.startswith(MorphisBlock.UUID):
        return data

    if MorphisBlock.parse_block_type(data) != BlockType.hash_tree.value:
        return data

    fetch = HashTreeFetch(engine, concurrency)
    return fetch.get(HashTreeBlock(data))

class HashTreeFetch(object):
    def __init__(self, engine, concurrency):
        self.engine = engine
        self.concurrency = concurrency

        self._task_semaphore = asyncio.Semaphore(concurrency)
        self._failed = []

    @asyncio.coroutine
    def fetch(self, root_block, data_callback):
        depth = block.depth
        buf = block.buf

        i = HashTreeBlock.HEADER_BYTES

        datas = yield from self._get_hash_tree_data(buf, i, depth)

        #TODO: YOU_ARE_HERE: wait combine datas.

    @asyncio.coroutine
    def _get_hash_tree_data(self, hash_tree_data, idx, depth):
        data_len = len(hash_tree_data)

        key_cnt = (data_len - idx) / chord.NODE_ID_BYTES
        datas = [None] * key_cnt

        for i in range(key_cnt):
            end = idx + chord.NODE_ID_BYTES
            data_key = hash_tree_data[idx:end]

            yield from self._task_semaphore.acquire()

            asyncio.async(\
                self.__get_hash_tree_data(data_key, datas, i),\
                loop=self.engine.loop)

            idx = end

        return datas

    @asyncio.coroutine
    def __get_hash_tree_data(self, datas, i):
        data_rw = yield from self.engine.tasks.send_get_data(data_key)
        if not data_rw.data:
            self._failed += {\
                depth: depth,
                idx: idx,
                data_key: data_key}
            continue

        if not depth:
            datas[i] += data_rw.data
        else:
            datas[i] = yield from\
                _get_hash_tree_data(data_rw.data, 0, depth - 1)

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
