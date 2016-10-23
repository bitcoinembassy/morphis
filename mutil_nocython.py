import llog

import asyncio
import itertools
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

if log.isEnabledFor(logging.INFO):
    task_id_seq = itertools.count()

@asyncio.coroutine
def retry_until(func, amount, max_retries, *args, **kwargs):
    total = 0
    if log.isEnabledFor(logging.INFO):
        task_id = task_id_seq.__next__()

    retry_factor = kwargs.get("retry_factor", 5)
    total_max_retries = retry_factor + max_retries

    while True:
        total += yield from func(*args, **kwargs)

        if total >= amount:
            return total

        retry_factor += 1

        if retry_factor >= total_max_retries:
            if "task_id" not in locals():
                task_id = None

            log.warning(\
                "Retry task (id=[{}], func_name=[{}]) reached max_retries"\
                " ({}) with total=[{}]."\
                    .format(task_id, func.__name__, max_retries, total))
            return total

        kwargs["retry_factor"] = retry_factor

        if log.isEnabledFor(logging.INFO):
            log.info("Retrying (id=[{}] func_name=[{}]) with"\
                "retry_factor=[{}]."\
                    .format(task_id, func.__name__, retry_factor))
##.

