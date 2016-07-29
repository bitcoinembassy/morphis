# Höfundarréttur (c) eilífur  Heimur-Heilinn
# License: GPL v2.

import llog

import asyncio
import logging
import time

from sqlalchemy.orm import joinedload

import base58
from db import DmailAddress
import dhgroup14
import dmail
import mbase32
import rsakey
import sshtype

log = logging.getLogger(__name__)

class DdsClientEngine(object):
    def __init__(self, node):
        self.node = node
        self.db = node.db
        self.loop = node.loop

        self.auto_scan_enabled = True

        self._running = False

        self._autoscan_task = None

    @asyncio.coroutine
    def start(self):
        if self._running:
            return

        self._running = True

        if self.auto_scan_enabled:
            self._autoscan_task =\
                asyncio.async(self._start_autoscan(), loop=self.loop)

    @asyncio.coroutine
    def stop(self):
        if not self._running:
            return

        if self._autoscan_task:
            _autoscan_task.cancel()

class DdsAutoscanProcess(object):
    def __init__(self, dce, target_key):
        self.dce = dce
        self.loop = dce.loop

        self.target_key = target_key

        self._task = None
        self._running = False

    def start(self):
        assert not self._running
        self._running = True
        self._task = asyncio.async(self._run(), loop=self.loop)

    def stop(self):
        if not self._running:
            return

        self._running = False
        self._task.cancel()
        self._task = None

    def _run(self):
        while self._running:
            #TODO: YOU_ARE_HERE
            pass
