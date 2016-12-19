# Copy pasted from asyncio/locks.py from the official Python source.
# This is done because a later version of Python moved this around or
# something. Thus to ensure compatibility with all versions of Python, we
# include it here.

#import collections

import asyncio
import python_compat as compat
#from asyncio import events
#from asyncio import futures
#from asyncio.coroutines import coroutine

class _ContextManager:
    """Context manager.
    This enables the following idiom for acquiring and releasing a
    lock around a block:
        with (yield from lock):
            <block>
    while failing loudly when accidentally using:
        with lock:
            <block>
    """

    def __init__(self, lock):
        self._lock = lock

    def __enter__(self):
        # We have no use for the "as ..."  clause in the with
        # statement for locks.
        return None

    def __exit__(self, *args):
        try:
            self._lock.release()
        finally:
            self._lock = None # Crudely prevent reuse.

class _ContextManagerMixin:
    def __enter__(self):
        raise RuntimeError(
            '"yield from" should be used as context manager expression')

    def __exit__(self, *args):
        # This must exist because __enter__ exists, even though that
        # always raises; that's how the with-statement works.
        pass

    @asyncio.coroutine
    def __iter__(self):
        # This is not a coroutine.  It is meant to enable the idiom:
        #
        #     with (yield from lock):
        #         <block>
        #
        # as an alternative to:
        #
        #     yield from lock.acquire()
        #     try:
        #         <block>
        #     finally:
        #         lock.release()
        yield from self.acquire()
        return _ContextManager(self)

    if compat.PY35:

        def __await__(self):
            # To make "with await lock" work.
            yield from self.acquire()
            return _ContextManager(self)

        @asyncio.coroutine
        def __aenter__(self):
            yield from self.acquire()
            # We have no use for the "as ..."  clause in the with
            # statement for locks.
            return None

        @asyncio.coroutine
        def __aexit__(self, exc_type, exc, tb):
            self.release()



