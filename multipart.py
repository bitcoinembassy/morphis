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
def store_data(engine, data, privatekey=None, path=None, version=None,\
        key_callback=None, store_key=True, concurrency=32):

    data_len = len(data)

    if data_len <= mnnode.MAX_DATA_BLOCK_SIZE:
        if log.isEnabledFor(logging.INFO):
            log.info("Data fits in one block, performing simple store.")

        if privatekey:
            yield from engine.tasks.send_store_updateable_key(\
                data, privatekey, path, version, key_callback)

            yield from engine.tasks.send_store_updateable_key_key(\
                data, privatekey, path, key_callback)
        else:
            yield from engine.tasks.send_store_data(data, key_callback)

            yield from engine.tasks.send_store_key(data)

        if log.isEnabledFor(logging.INFO):
            log.info("Simple store complete.")

        return

    yield from _store_data(engine, data, key_callback, concurrency)

def __key_callback(keys, idx, key):
    key_len = len(key)
    idx = key_len * idx
    keys[idx:idx+key_len] = key

@asyncio.coroutine
def _store_data(engine, data, key_callback, concurrency):
    depth = 1
    task_semaphore = asyncio.Semaphore(concurrency)

    data_len = len(data)
    assert data_len > mnnode.MAX_DATA_BLOCK_SIZE

    while True:
        nblocks = data_len / mnnode.MAX_DATA_BLOCK_SIZE
        if data_len % mnnode.MAX_DATA_BLOCK_SIZE:
            nblocks += 1

        keys = bytearray(nblocks * chord.NODE_ID_BYTES)

        start = 0
        end = mnnode.MAX_DATA_BLOCK_SIZE

        tasks = []

        for i in range(nblocks):
            _key_callback = functools.partial(__key_callback, keys, i)

            tasks += asyncio.async(\
                _store_block(\
                    engine, data[start:end], i, _key_callback, task_semaphore))

            yield from task_semaphore.acquire()

            done, pending = yield from asyncio.wait(tasks, loop=engine.loop,\
                return_when=futures.FIRST_COMPLETED)

            for task in done:
                if not task.result():
                    log.warning("Upload failed!")
                    return False

            start = end
            end += mnnode.MAX_DATA_BLOCK_SIZE
            if end > data_len:
                assert i == (nblocks - 1)
                end = data_len

        # Wait for all previous hashes to be done. This simplifies the code, as
        # otherwise we have to track which are done to make sure we are not
        # uploading a block of hashes that is not complete.
        done, pending = yield from asyncio.wait(tasks, loop=engine.loop)

        data = keys
        data_len = len(data)
        if data_len\
                <= (mnnode.MAX_DATA_BLOCK_SIZE - MorphisBlock.HEADER_BYTES):
            break

        depth += 1

    # Store root MorphisBlock.
    block = HashTreeBlock()
    block.depth = depth
    block.data = keys

    yield from\
        _store_block(engine, block.encode(), _key_callback, task_semaphore)

@asyncio.coroutine
def _store_block(engine, i, block_data, key_callback, task_semaphore):
    snodes = yield from engine.tasks.send_store_data(block_data, key_callback)

    if not snodes:
        log.warning("Failed to upload block #{}.".format(i))

    task_semaphore.release()

class BlockType(Enum):
    hash_tree = 0
    user = 1

class MorphisBlock(object):
    HEADER_BYTES = 64

    uuid = b'\x86\xa0\x47\x79\xc1\x2e\x4f\x48\x90\xc3\xee\x27\x53\x6d\x26\x96'

    def __init__(self, block_type=None, buf=None):
        self.buf = buf
        self.block_type = block_type

        if not buf:
            return

        self.parse()

    def encode(self):
        nbuf = bytearray()

        nbuf += MorphisBlock.uuid
        nbuf += struct.pack(">L", self.block_type)
        nbuf += struct.pack(">L", self.ext_type)

        self.buf = nbuf

        return nbuf

    def parse(self):
        assert self.buf[:16] == MorphisBlock.uuid
        i = 16

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
    def __init__(self, buf=None):
        self.depth = 0

        super().__init__(BlockType.hash_tree.value, buf)

    def encode(self):
        nbuf = super().encode()
        nbuf += struct.pack(">L", self.depth)

        nbuf += b' ' * (chord.NODE_ID_BYTES - len(nbuf))

        return nbuf

    def parse(self):
        i = super().parse()

        self.depth = struct.unpack_from(">L", self.buf, i)
