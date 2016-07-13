# Copyright (c) 2016  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
import logging

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
        self.tasks = node.engine.tasks
        self.db = node.db
        self.loop = node.loop

    def create_synapse(\
            self, target_key, source_key, key, stamps=None, timestamp=None):
        s = syn.Synapse()
        s.target_key = target_key
        s.source_key = source_key
        s.key = key
        if timestamp:
            s.timestamp = timestamp
        s.stamps = stamps

        return s

    @asyncio.coroutine
    def upload_synapse(self, synapse):
        synapse_key = None

        def key_callback(key):
            nonlocal synapse_key
            synapse_key = key

        # Upload the TargetedBlock to the network.
        log.info("Sending Synapse to the network.")

        total_storing = 0
        retry = 0
        while True:
            storing_nodes = yield from\
                self.tasks.send_store_synapse(\
                    synapse, store_key=True, key_callback=key_callback,
                    retry_factor=retry*10)

            total_storing += storing_nodes

            if total_storing >= 3:
                break

            if retry > 32:
                break
            elif retry > 3:
                yield from asyncio.sleep(1)

            retry += 1

        key_enc = mbase32.encode(synapse_key)
        id_enc = mbase32.encode(enc.generate_ID(synapse_key))

        if log.isEnabledFor(logging.INFO):
            log.info("Synapse sent; key=[{}], id=[{}], storing_nodes=[{}]."\
                .format(key_enc, id_enc, total_storing))
