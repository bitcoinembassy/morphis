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
import dds
import mbase32
import rsakey
import sshtype

log = logging.getLogger(__name__)

class DdsQuery(object):
    def __init__(self, target_key):
        self.target_key =\
            target_key if type(target_key) is bytes else bytes(target_key)

    def __hash__(self):
        return hash(self.target_key)

    def __eq__(self, other):
        return self.target_key == other.target_key

    def __ne__(self, other):
        return not(self == other)

class DdsClientEngine(object):
    def __init__(self, node):
        self.node = node
        self.db = node.db
        self.loop = node.loop

        self.dds_engine = dds.DdsEngine(node)

        self._running = False

        self._autoscan_processes = {}

    @asyncio.coroutine
    def start(self):
        if self._running:
            return

        self._running = True

    @asyncio.coroutine
    def stop(self):
        if not self._running:
            return

    def add_query_listener(self, query, listener):
        assert type(query) is DdsQuery

        process = self.enable_query_autoscan(query, False)
        process.add_listener(listener)

    def check_query_autoscan(self, query):
        return query in self._autoscan_processes

    def enable_query_autoscan(self, query, persistent=True):
        assert type(query) is DdsQuery

        process = self._autoscan_processes.get(query)
        if process:
            process.persistent = True
            return process

        process = DdsAutoscanProcess(self, query, persistent)
        process.start()

        self._autoscan_processes[query] = process

        return process

class DdsAutoscanProcess(object):
    def __init__(self, dce, query, persistent):
        self.dce = dce
        self.loop = dce.loop
        self.query = query
        self.persistent = persistent

        self._task = None
        self._running = False

        self._listeners = []

    def start(self):
        assert not self._running
        if log.isEnabledFor(logging.INFO):
            log.info("Starting autoscan for target_key=[{}]."\
                .format(mbase32.encode(self.query.target_key)))

        self._running = True
        self._task = asyncio.async(self._run(), loop=self.loop)

    def stop(self):
        if not self._running:
            return

        self._running = False
        self._task.cancel()
        self._task = None

    def add_listener(self, listener):
        self._listeners.append(listener)

    def remove_listener(self, listener):
        self._listeners.remove(listener)

    @asyncio.coroutine
    def _notify_listeners(self, post):
        for listener in self._listeners:
            yield from listener(post)

    @asyncio.coroutine
    def _run(self):
        while self._running:
            if log.isEnabledFor(logging.INFO):
                log.info("DdsAutoscanProcess scanning target_key=[{}] now."\
                    .format(mbase32.encode(self.query.target_key)))

            yield from self.dce.dds_engine.scan_target_key(\
                self.query.target_key, self._notify_listeners)
            # Let listeners know that the scan finished.
            yield from self._notify_listeners(None)
