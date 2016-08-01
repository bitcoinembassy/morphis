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

class DmailClientEngine(object):
    def __init__(self, node):
        self.node = node
        self.db = node.db
        self.loop = node.loop

        self.dmail_engine = dmail.DmailEngine(node)

        self.auto_publish_enabled = True
        self.auto_scan_enabled = True

        self._running = False

        self._dmail_autoscan_processes = {}

    @asyncio.coroutine
    def start(self):
        if self._running:
            return

        self._running = True

        if self.auto_scan_enabled:
            asyncio.async(self._start_dmail_autoscan(), loop=self.loop)
        if self.auto_publish_enabled:
            asyncio.async(self._start_dmail_auto_publish(), loop=self.loop)

    @asyncio.coroutine
    def stop(self):
        if not self._running:
            return

        self._running = False

        for processor in self._dmail_autoscan_processes.values():
            processor.stop()

    @asyncio.coroutine
    def _start_dmail_auto_publish(self):
        yield from self.node.engine.protocol_ready.wait()

        def dbcall():
            with self.db.open_session(True) as sess:
                q = sess.query(DmailAddress)\
                    .options(joinedload("keys"))

                r = q.all()

                sess.expunge_all()

                return r

        while self._running:
            addrs = yield from self.loop.run_in_executor(None, dbcall)

            for addr in addrs:
                yield from self._dmail_auto_publish(addr)

            log.info("Finished auto-publish scan, sleeping for now.")

            yield from asyncio.sleep(60 * 60 * 24, loop=self.loop)

    @asyncio.coroutine
    def _dmail_auto_publish(self, dmail_address):
        data_rw = yield from self.node.engine.tasks.send_get_data(\
            dmail_address.site_key, retry_factor=100)

        if data_rw.data:
            if log.isEnabledFor(logging.DEBUG):
                log.debug("Succeeded in fetching dmail site [{}]; won't"\
                    " auto-publish."\
                        .format(mbase32.encode(dmail_address.site_key)))
            return

        if log.isEnabledFor(logging.INFO):
            log.info("Failed to fetch dmail site [{}]; republishing."\
                .format(mbase32.encode(dmail_address.site_key)))

        private_key = rsakey.RsaKey(privdata=dmail_address.site_privatekey)

        dh = dhgroup14.DhGroup14()
        dh.x = sshtype.parseMpint(dmail_address.keys[0].x)[1]
        dh.generate_e()

        dms = dmail.DmailSite()
        root = dms.root
        root["ssm"] = "mdh-v1"
        root["sse"] = base58.encode(sshtype.encodeMpint(dh.e))
        root["target"] =\
            mbase32.encode(dmail_address.keys[0].target_key)
        root["difficulty"] = int(dmail_address.keys[0].difficulty)

        storing_nodes =\
            yield from self.dmail_engine.publish_dmail_site(private_key, dms)

        if log.isEnabledFor(logging.INFO):
            log.info("Republished Dmail site with [{}] storing nodes."\
                .format(storing_nodes))

    @asyncio.coroutine
    def _start_dmail_autoscan(self):
        yield from self.node.engine.protocol_ready.wait()

        def dbcall():
            with self.db.open_session(True) as sess:
                q = sess.query(DmailAddress)\
                    .options(joinedload("keys"))\
                    .filter(DmailAddress.scan_interval > 0)

                r = q.all()

                sess.expunge_all()

                return r

        addrs = yield from self.loop.run_in_executor(None, dbcall)

        for addr in addrs:
            self.update_dmail_autoscan(addr)

    def update_dmail_autoscan(self, addr):
        if not self.auto_scan_enabled:
            return

        if log.isEnabledFor(logging.INFO):
            log.info(\
                "Starting/Updating autoscan (scan_interval=[{}]) process for"\
                " DmailAddress (id=[{}])."\
                    .format(addr.scan_interval, addr.id))

        process = self._dmail_autoscan_processes.get(addr.id)

        if not addr.scan_interval:
            if process:
                process.stop()
                del self._dmail_autoscan_processes[addr.id]
            else:
                return

        if process:
            process.update_scan_interval(addr.scan_interval)
        else:
            process = DmailAutoscanProcess(self, addr, addr.scan_interval)
            asyncio.async(process.run(), loop=self.loop)
            self._dmail_autoscan_processes[addr.id] = process

    def trigger_dmail_scan(self, addr):
        if log.isEnabledFor(logging.INFO):
            log.info("Ensuring scan of DmailAddress (id=[{}]) now."\
                .format(addr.id))

        process = self._dmail_autoscan_processes.get(addr.id)

        if process:
            process.scan_now()
        else:
            process = DmailAutoscanProcess(self, addr, 0)
            asyncio.async(process.run(), loop=self.loop)
            self._dmail_autoscan_processes[addr.id] = process

class DmailAutoscanProcess(object):
    def __init__(self, dce, addr, interval):
        self.dce = dce
        self.loop = dce.loop
        self.dmail_address = addr
        self.scan_interval = interval

        self._running = False
        self._task = None
        self._scan_now = False

    def scan_now(self):
        if self._task:
            self._scan_now = True
            self._task.cancel()
        else:
            if self._running:
                log.info("Already scanning.")
                return
            asyncio.async(self.run(), loop=self.loop)

    def update_scan_interval(self, interval):
        if not interval:
            self._running = False
            if self._task:
                self._task.cancel()
            return

        self.scan_interval = interval

        if self._running:
            if log.isEnabledFor(logging.INFO):
                log.info("Notifying DmailAutoscanProcess (addr=[{}]) of"\
                    " interval change."\
                        .format(mbase32.encode(self.dmail_address.site_key)))
            if self._task:
                self._task.cancel()
        else:
            if log.isEnabledFor(logging.INFO):
                log.info("Starting DmailAutoscanProcess (addr=[{}])."\
                    .format(mbase32.encode(self.dmail_address.site_key)))
            asyncio.async(self.run(), loop=self.loop)

    @asyncio.coroutine
    def run(self):
        self._running = True

        if log.isEnabledFor(logging.INFO):
            addr_enc = mbase32.encode(self.dmail_address.site_key)
            log.info("DmailAutoscanProcess (addr=[{}]) running."\
                .format(addr_enc))

        while self._running:
            new_cnt, old_cnt, err_cnt = yield from\
                self.dce.dmail_engine.scan_and_save_new_dmails(\
                    self.dmail_address)

            if log.isEnabledFor(logging.INFO):
                log.info("Finished scanning Dmails for address [{}];"\
                    " new_cnt=[{}], old_cnt=[{}], err_cnt=[{}]."\
                        .format(addr_enc, new_cnt, old_cnt, err_cnt))

            if not self.scan_interval:
                self._running = False

            if not self._running:
                break

            time_left = self.scan_interval
            start = time.time()

            while time_left > 0:
                if log.isEnabledFor(logging.INFO):
                    log.info("DmailAutoscanProcess sleeping for [{}] seconds."\
                        .format(time_left))

                self._task =\
                    asyncio.async(\
                        asyncio.sleep(time_left, loop=self.loop),\
                        loop=self.loop)

                try:
                    yield from self._task
                    self._task = None
                    break
                except asyncio.CancelledError:
                    self._task = None
                    if log.isEnabledFor(logging.INFO):
                        log.info("Woken from sleep for address [{}]."\
                            .format(\
                                mbase32.encode(self.dmail_address.site_key)))
                    if self._scan_now:
                        self._scan_now = False
                        break
                    time_left = self.scan_interval - (time.time() - start)

    def stop(self):
        if self._running:
            if log.isEnabledFor(logging.INFO):
                log.info("Stopping DmailAutoscanProcess (addr=[{}])."\
                    .format(mbase32.encode(self.dmail_address.site_key)))
            self._running = False
            if self._task:
                self._task.cancel()

