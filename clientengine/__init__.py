# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
import logging
import os

import base58
import chord
from clientengine import dmail
from clientengine import dds
import mbase32
import multipart

log = logging.getLogger(__name__)

class ClientEngine(object):
    def __init__(self, node):
        self.node = node
        self.loop = node.loop

        self.dds = dds.DdsClientEngine(node)
        self.dmail = dmail.DmailClientEngine(node)

        self.latest_version_number = None
        self.latest_version_data = None

        #FIXME: Why is this here? It should be in Maalstroom somewhere.
        self.csrf_token = base58.encode(os.urandom(64))

        self.version_check_enabled = True

        self._running = False

        self._data_key =\
            mbase32.decode("sp1nara3xhndtgswh7fznt414we4mi3y6kdwbkz4jmt8ocb6x"\
                "4w1faqjotjkcrefta11swe3h53dt6oru3r13t667pr7cpe3ocxeuma")
        self._path = b"latest_version"

        self._version_poller_task = None

    @property
    def update_test(self):
        raise Exception()

    @update_test.setter
    def update_test(self, value):
        if value:
            self._path = b"test_version"
            self.latest_version_number = "0.0.1"

    @asyncio.coroutine
    def start(self):
        if self._running:
            return

        self._running = True

        yield from self.dds.start()
        yield from self.dmail.start()

        if self.version_check_enabled:
            self._version_poller_task =\
                asyncio.async(self._start_version_poller(), loop=self.loop)

    def stop(self):
        if not self._running:
            return

        self._running = False

        self.dds.stop()
        self.dmail.stop()

        if self._version_poller_task:
            self._version_poller_task.cancel()

    @asyncio.coroutine
    def _start_version_poller(self):
        yield from self.node.engine.protocol_ready.wait()

        while self._running:
            data_rw = multipart.BufferingDataCallback()

            r =\
                yield from\
                    multipart.get_data(self.node.engine, self._data_key,\
                        data_callback=data_rw, path=self._path)

            if data_rw.data:
                if data_rw.version:
                    data = data_rw.data.decode()

                    p0 = data.find('<span id="version_number">')
                    p0 += 26
                    p1 = data.find("</span>", p0)
                    self.latest_version_number = data[p0:p1]
                    self.latest_version_data = data

                    if log.isEnabledFor(logging.INFO):
                        log.info("Found latest_version_number=[{}]"\
                            " (data_rw.version=[{}])."\
                                .format(\
                                    self.latest_version_number,\
                                    data_rw.version))
                else:
                    if log.isEnabledFor(logging.INFO):
                        log.info("Found invalid latest_version record:"\
                            " data_rw.version=[{}], len(data)=[{}]."\
                                .format(data_rw.version, len(data_rw.data)))
                delay = 5*60
            else:
                log.info("Couldn't find latest_version in network.")
                delay = 60

            yield from asyncio.sleep(delay, loop=self.loop)
