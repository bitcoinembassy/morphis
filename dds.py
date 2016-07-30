# Copyright (c) 2016  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
import logging

from sqlalchemy import or_

from db import DdsPost
import dpush
import enc
import mbase32
import mutil
import synapse as syn

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
    def scan_target_key(self, target_key):
        pass

    @asyncio.coroutine
    def retrieve_post(self, key, target_key=None):
        if type(key) is syn.Synapse:
            assert not target_key
            synapse = key
            key = synapse.synapse_key
            target_key = synapse.target_key
        else:
            synapse = None

        post = yield from self._load_dds_post(key)

        if post:
            return post

        if not target_key:
            # Plain static data.
            data_rw = yield from\
                self.node.engine.tasks.send_get_data(bytes(key))

            obj = None
        else:
            # TargetedBlock or Synapse.
            if synapse:
                obj = synapse
            else:
                data_rw =\
                    yield from self.node.engine.tasks.send_get_targeted_data(\
                        bytes(key), target_key=target_key)
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
            yield from self._save_dds_post(key, target_key, obj, data_rw.data)

        return post

    @asyncio.coroutine
    def _load_dds_post(self, key):
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
    def _save_dds_post(self, key, target_key, obj, data):
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
