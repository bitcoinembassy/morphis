import llog

import asyncio
import logging
import queue

import mutil

log = logging.getLogger(__name__)

## yield from helper.
class ExceptionResult(object):
    def __init__(self, exception):
        self.exception = exception

@asyncio.coroutine
def _yield_from(coroutine, result_queue):
    try:
        r = yield from coroutine
        result_queue.put(r)
    except Exception as e:
        log.exception(e)
        result_queue.put(mutil.ExceptionResult(e))

def _schedule_yield_from(coroutine, result_queue):
    task = asyncio.async(_yield_from(coroutine, result_queue))

def yield_from_thread_safe(loop, coroutine):
    result_queue = queue.Queue()
    loop.call_soon_threadsafe(_schedule_yield_from, coroutine, result_queue)
    r = result_queue.get()
    if type(r) is ExceptionResult:
        raise r.exception
    return r
##.

