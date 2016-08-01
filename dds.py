# Copyright (c) 2016  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
from concurrent import futures
import logging

from sqlalchemy import or_

from db import DdsPost
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
        "Returns through post_callback only new posts."
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
            exists = yield from self.check_has_post(key)
            if exists:
                return

            post = yield from self.fetch_post(key, target_key)

            if not post:
                if log.isEnabledFor(logging.INFO):
                    log.info("Data not found for found targeted key [{}]."\
                        .format(mbase32.encode(key)))
                return

            yield from post_callback(post)

        @asyncio.coroutine
        def process_synapse(synapse):
            exists = yield from self.check_has_post(synapse.synapse_key)
            if exists:
                return

            post = yield from self.fetch_post(synapse, target_key)

            if not post:
                if log.isEnabledFor(logging.INFO):
                    log.info("Synapse content not found for key [{}]."\
                        .format(mbase32.encode(synapse.content_key)))
                return

            yield from post_callback(post)

        @asyncio.coroutine
        def key_cb(key):
            nonlocal new_tasks

            if type(key) is bytearray:
                key = bytes(key)

            if key in loaded:
                if log.isEnabledFor(logging.INFO):
                    log.info("Skipping already loaded TargetedBlock/Synapse"\
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
                    if log.isEnabledFor(logging.INFO):
                        log.info(\
                            "Skipping already loaded Synapse for key=[{}]."\
                                .format(mbase32.encode(key)))
                    continue

                loaded.add(key)

                new_tasks.append(\
                    asyncio.async(\
                        process_synapse(synapse),\
                        loop=self.loop))

        new_tasks.append(asyncio.async(\
                self.dpush_engine.scan_targeted_blocks(target_key, 8, key_cb)))
        new_tasks.append(self.node.engine.tasks.send_get_synapses(\
            target_key, result_callback=syn_cb, retry_factor=25))

        tasks = new_tasks.copy()
        new_tasks.clear()

        while tasks:
            done, pending = yield from asyncio.wait(\
                tasks, loop=self.loop, return_when=futures.ALL_COMPLETED)

            tasks = new_tasks.copy()
            new_tasks.clear()

            if pending:
                tasks.extend(pending)

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
        if not target_key:
            # Plain static data.
            data_rw = yield from\
                self.node.engine.tasks.send_get_data(bytes(key))

            obj = None
        else:
            # TargetedBlock or Synapse.
            if type(key) is syn.Synapse:
                obj = key
                key = key.synapse_key
            else:
                if type(key) is not bytes:
                    key = bytes(key)

                data_rw =\
                    yield from self.node.engine.tasks.send_get_targeted_data(\
                        key, target_key=target_key)
                obj = data_rw.object

            if obj:
                if type(obj) is syn.Synapse:
                    data_rw = yield from\
                        self.node.engine.tasks.send_get_data(obj.source_key)
                else:
                    assert type(obj) is tb.TargetedBlock, type(obj)
                    data_rw.data = data_rw.data[tb.TargetedBlock.BLOCK_OFFSET:]

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
            log.info("Saving DdsPost for key=[{}], target_key=[{}]."\
                .format(mbase32.encode(key), mbase32.encode(target_key)))

        def dbcall():
            with self.db.open_session() as sess:
                post = DdsPost()

                post.first_seen = mutil.utc_datetime()
                post.data = data

                if obj:
                    assert target_key
                    post.target_key = target_key

                    if type(obj) is syn.Synapse:
                        post.synapse_key = obj.synapse_key
                        post.synapse_pow = obj.synapse_pow
                        post.data_key = obj.source_key
                        if obj.is_signed():
                            post.signing_key = obj.signing_key
                        post.timestamp = mutil.utc_datetime(obj.timestamp)
                    else:
                        assert type(obj) is tb.TargetedBlock, type(obj)
                        post.data_key = post.synapse_pow = key
                        post.timestamp = mutil.utc_datetime(0)
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
