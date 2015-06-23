import llog

import asyncio
import loggin

import chord
from mutil import hex_string
import node as mnnode
import peer as mnpeer
import sshtype

log = logging.getLogger(__name__)

@asyncio.coroutine
def store_data(engine, data, privatekey=None, path=None, version=None,\
        key_callback=None, store_key=True, concurrency=10):

    data_len = len(data)

    if data_len <= node.MAX_DATA_BLOCK_SIZE:
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

    yield from _store_data(engine, data, concurrency)

@asyncio.coroutine
def _store_data(engine, data, concurrency):

    task_semaphore = asyncio.Semaphore(concurrency)
    block_queue = asyncio.Queue()

    store_tasks = []

    for i in range(concurrency):
        task = asyncio.async(
        store_tasks.append(task)

    while True:


    nblocks = data_len / node.MAX_DATA_BLOCK_SIZE
