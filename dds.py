# Copyright (c) 2016  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
from concurrent import futures
import logging

from sqlalchemy import or_, func

import consts
from db import DdsPost, DdsStamp
import dpush
import enc
import mbase32
import mutil
import synapse as syn
import targetedblock as tb

log = logging.getLogger(__name__)

class DdsEngine(object):
    @staticmethod
    def calc_key_for_channel(channel_name):
        #TODO: Come up with a formal spec. We should probably deal with
        # unprintable characters by merging them, Etc.
        str_id = channel_name.lower().encode()
        return enc.generate_ID(str_id)

    def __init__(self, node):
        self.node = node
        self.db = node.db
        self.loop = node.loop

        self.dpush_engine = dpush.DpushEngine(node)

    @asyncio.coroutine
    def scan_target_key(self, target_key, post_callback, skip=None):
        "Perpetually scan until task is cancelled. Posts are reported through"\
        " post_callback only new posts."
        if skip:
            if type(skip) is set:
                loaded = skip
            else:
                assert type(skip) is list
                loaded = set(skip)
        else:
            loaded = set()

        new_tasks = []

        @asyncio.coroutine
        def process_key(key):
            assert type(key) in (bytes, bytearray)
            log.debug("process_key(): called.")

            exists = yield from self.check_has_post(key)
            if exists:
                return

            post = yield from self.fetch_post(key, target_key)

            if not post:
                if log.isEnabledFor(logging.DEBUG):
                    log.debug("Data not found for found targeted key [{}]."\
                        .format(mbase32.encode(key)))
                return

            if log.isEnabledFor(logging.INFO):
                log.info(\
                    "Found new DdsPost via targeted (key=[{}], type=[{}])."\
                        .format(\
                            mbase32.encode(key),\
                            type(post)))

            yield from post_callback(post)

        @asyncio.coroutine
        def process_synapse(synapse):
            db_stamps = []

            if log.isEnabledFor(logging.DEBUG):
                log.debug("Synapse [{}] has [{}] StampS.".format(\
                    mbase32.encode(synapse.synapse_key), len(synapse.stamps)))

            def dbcall():
                with self.db.open_session() as sess:
                    updates = False
                    for stamp in synapse.stamps:
                        q = sess.query(func.count("*"))\
                            .select_from(DdsStamp)\
                            .filter(\
                                DdsStamp.signed_key == stamp.signed_key,\
                                DdsStamp.version == stamp.version,\
                                DdsStamp.signing_key == stamp.signing_key)\

                        if q.scalar():
                            if log.isEnabledFor(logging.INFO):
                                log.info("Skipping existing DdsStamp.")
                            continue

                        if log.isEnabledFor(logging.INFO):
                            log.info("Inserting new DdsStamp!")

                        dbs = DdsStamp()
                        dbs.signed_key = stamp.signed_key
                        dbs.version = stamp.version
                        dbs.signing_key = stamp.signing_key
                        dbs.difficulty =\
                            consts.NODE_ID_BITS - stamp.log_distance[0]
                        dbs.first_seen = mutil.utc_datetime()

                        sess.add(dbs)
                        updates = True

                    if updates:
                        sess.commit()

            # Update DdsStampS.
            yield from self.loop.run_in_executor(None, dbcall)

            exists = yield from self.check_has_post(synapse.synapse_key)
            if exists:
                if log.isEnabledFor(logging.INFO):
                    log.info(\
                        "Synapse (synapse_key=[{}]) is already in local db."\
                            .format(mbase32.encode(synapse.synapse_key)))
                return

            post = yield from self.fetch_post(synapse)

            if not post:
                if log.isEnabledFor(logging.DEBUG):
                    log.debug("Synapse content not found for key [{}]."\
                        .format(mbase32.encode(synapse.source_key)))
                return

            if log.isEnabledFor(logging.INFO):
                log.info(\
                    "Found new Synapse (synapse_key=[{}], len(stamps)=[{}])."\
                        .format(\
                            mbase32.encode(synapse.synapse_key),\
                            len(synapse.stamps)))

            yield from post_callback(post)

        @asyncio.coroutine
        def key_cb(key):
            nonlocal new_tasks

            if type(key) is bytearray:
                key = bytes(key)

            if key in loaded:
                if log.isEnabledFor(logging.DEBUG):
                    log.debug("Skipping already seen TargetedBlock/Synapse"\
                        " for key=[{}].".format(mbase32.encode(key)))
                return

            loaded.add(key)

            new_tasks.append(\
                asyncio.async(\
                    process_key(key),\
                    loop=self.loop))

        @asyncio.coroutine
        def syn_cb(data_rw):
            nonlocal new_tasks

            for synapse in data_rw.data:
                key = synapse.synapse_pow
                if type(key) is bytearray:
                    key = bytes(key)

                if key in loaded:
                    if log.isEnabledFor(logging.DEBUG):
                        log.debug(\
                            "Skipping already seen Synapse for key=[{}]."\
                                .format(mbase32.encode(key)))
                    continue

                loaded.add(key)

                new_tasks.append(\
                    asyncio.async(\
                        process_synapse(synapse),\
                        loop=self.loop))

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Scanning target_key=[{}]."\
                .format(mbase32.encode(target_key)))

        @asyncio.coroutine
        def tb_task():
            while True:
                yield from self.dpush_engine.scan_targeted_blocks(\
                    target_key, 8, key_cb)
                # Old style poll only every 5 minutes.
                yield from asyncio.sleep(300)

        @asyncio.coroutine
        def st_task():
            while True:
                yield from self.node.engine.tasks.send_get_synapses(\
                    target_key, stamp_key=target_key, result_callback=syn_cb,\
                    retry_factor=25)
                yield from asyncio.sleep(5)

        @asyncio.coroutine
        def sk_task():
            while True:
                yield from self.node.engine.tasks.send_get_synapses(\
                    signing_key=target_key, result_callback=syn_cb,\
                    retry_factor=25)
                yield from asyncio.sleep(1)

        @asyncio.coroutine
        def sy_task():
            while True:
                yield from self.node.engine.tasks.send_get_synapses(\
                    target_key, result_callback=syn_cb, retry_factor=25)
                yield from asyncio.sleep(1)

        new_tasks.append(asyncio.async(tb_task(), loop=self.loop))
        new_tasks.append(asyncio.async(st_task(), loop=self.loop))
        new_tasks.append(asyncio.async(sk_task(), loop=self.loop))
        new_tasks.append(asyncio.async(sy_task(), loop=self.loop))

        tasks = new_tasks.copy()
        new_tasks.clear()

        while tasks:
            try:
                done, pending = yield from asyncio.wait(\
                    tasks, loop=self.loop, return_when=futures.ALL_COMPLETED)
            except asyncio.CancelledError as e:
                for task in new_tasks:
                    if not task.done():
                        task.cancel()
                raise e

            tasks = new_tasks.copy()
            new_tasks.clear()

    @asyncio.coroutine
    def check_has_post(self, key):
        def dbcall():
            with self.db.open_session(True) as sess:
                q = sess.query(DdsPost)\
                    .filter(\
                        or_(\
                            DdsPost.synapse_key == key,\
                            DdsPost.synapse_pow == key,\
                            DdsPost.data_key == key))

                return bool(q.count())

        return (yield from self.loop.run_in_executor(None, dbcall))

    @asyncio.coroutine
    def fetch_post(self, key, target_key=None):
        if type(key) is syn.Synapse:
            # Synapse.
            obj = key
            key = obj.synapse_key
            data_rw = yield from\
                self.node.engine.tasks.send_get_data(obj.source_key)
        else:
            if target_key:
                # TargetedData.
                if type(key) is not bytes:
                    key = bytes(key)

                data_rw =\
                    yield from self.node.engine.tasks.send_get_targeted_data(\
                        key, target_key=target_key)
                obj = data_rw.object

                if obj:
                    assert type(obj) is tb.TargetedBlock, type(obj)
                    data_rw.data = data_rw.data[tb.TargetedBlock.BLOCK_OFFSET:]

            else:
                # Plain static data.
                obj = None
                data_rw = yield from\
                    self.node.engine.tasks.send_get_data(bytes(key))

        if not data_rw.data:
            return None

        # Cache the 'post' locally.
        post =\
            yield from self.save_post(key, target_key, obj, data_rw.data)

        return post

    @asyncio.coroutine
    def load_post(self, key):
        def dbcall():
            with self.db.open_session(True) as sess:
                q = sess.query(DdsPost).filter(
                    or_(\
                        DdsPost.synapse_key == key,\
                        DdsPost.synapse_pow == key,\
                        DdsPost.data_key == key))

                return q.first()

        return (yield from self.loop.run_in_executor(None, dbcall))

    @asyncio.coroutine
    def save_post(self, key, target_key, obj, data):
        if log.isEnabledFor(logging.INFO):
            tk_e = mbase32.encode(target_key) if target_key else None
            log.info("Saving DdsPost for key=[{}], target_key=[{}]."\
                .format(mbase32.encode(key), tk_e))

        def dbcall():
            with self.db.open_session() as sess:
                post = DdsPost()

                post.first_seen = mutil.utc_datetime()
                post.data = data

                if obj:
                    if type(obj) is syn.Synapse:
                        target_keys = obj.target_keys
                        post.target_key = target_keys[0]
                        if len(target_keys) > 1:
                            post.target_key2 = target_keys[1]
                        post.synapse_key = obj.synapse_key
                        post.synapse_pow = obj.synapse_pow
                        post.data_key = obj.source_key
                        if obj.is_signed():
                            post.signing_key = obj.signing_key
                        post.timestamp = mutil.utc_datetime(obj.timestamp)
                        post.score =\
                            consts.NODE_ID_BITS - obj.log_distance[0]
                    else:
                        assert type(obj) is tb.TargetedBlock, type(obj)
                        post.target_key = target_key
                        post.data_key = post.synapse_pow = key
                        post.timestamp = mutil.utc_datetime(0)
                        post.score =\
                            consts.NODE_ID_BITS\
                                - mutil.calc_log_distance(target_key, key)[0]
                else:
                    post.data_key = key
                    post.timestamp = post.first_seen

                sess.add(post)

                sess.commit()

                # Make sure data is loaded for use by caller.
                len(post.data)

                sess.expunge_all()

                return post

        return (yield from self.loop.run_in_executor(None, dbcall))
