# Höfundarréttur (c) eilífur  Heimur-Heilinn
# License: GPL v2.

import llog

import asyncio
from collections import deque
import logging

import python_locks

log = logging.getLogger(__name__)

class MultiLock(python_locks._ContextManagerMixin):
    def __init__(self, key_space=None, keys=None):
        self.key_space = {} if key_space is None else key_space

        self._locked = False
        self._our_lock_lists = []
        self._keys = keys

#    def __enter__(self):
#        if self._keys:
#            self.acquire(keys)
#        return self
#
#    def __exit__(self, type, value, tb):
#        if type is not None:
#            # An exception happened.
#            pass
#        if self._keys:
#            self.release()

    @asyncio.coroutine
    def acquire(self, keys=None):
        if self._locked:
            raise Exception("Already locked.")

        if not keys:
            keys = self._keys
            if not keys:
                self._locked = True
                return

        our_wait_locks = []

        new_list = deque([None])

        # Check each key for being locked; if not locked, lock it.
        for key in keys:
            locks = self.key_space.setdefault(key, new_list)

            if locks is not new_list:
                # Key already locked, add an Event so locker can notify us when
                # it is done.
                lock = asyncio.Event()
                locks.append(lock)
                our_wait_locks.append(lock)
            else:
                # Key was not locked; it is now claimed by [None] list added.
                # Prepare new new_list for next possible key.
                new_list = deque([None])

            self._our_lock_lists.append((key, locks))

        if our_wait_locks:
            # There were locked keys, wait for them.
            for lock in our_wait_locks:
                yield from lock.wait()

        # At this point, we own locks on all our keys; we can proceed.
        self._locked = True

    def release(self):
        if not self._locked:
            raise Exception("Not locked.")

        for key, lock_list in self._our_lock_lists:
            # Remove our lock.
            lock_list.popleft()

            if len(lock_list):
                # If there is another MultiLock waiting, notify it we are done.
                lock_list[0].set()
            else:
                # No more locks, remove empty array from dict to save memory.
                del self.key_space[key]

        self._locked = False
