# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
from collections import namedtuple
from concurrent import futures
from datetime import datetime
import logging
import math
import os
import random

from sqlalchemy import func, and_, or_
from sqlalchemy.orm import joinedload, aliased

import bittrie
import chord
import chord_packet as cp
from chordexception import ChordException
import consts
from db import Peer, DataBlock, NodeState, Synapse, SynapseKey
import mbase32
from morphisblock import MorphisBlock
import mutil
import enc
import node as mnnode
import peer as mnpeer
import rsakey
import sshtype
import synapse as syn
import targetedblock as tb

log = logging.getLogger(__name__)
log2 = logging.getLogger(__name__ + ".datastore")

class Counter(object):
    def __init__(self, value=None):
        self.value = value

#TODO: The existence of the following (DataResponseWrapper) is the indicator
# that we should really refactor this whole file into a new class that is an
# instance per request.
class DataResponseWrapper(object):
    def __init__(self, data_key):
        self.data_key = data_key
        self.data = None
        self.object = None
        self.pubkey = None
        self.signature = None
        self.path_hash = b""
        self.version = None
        self.targeted = False
        self.target_key = None
        self.data_done = None
        self.data_present_cnt = 0
        self.will_store_cnt = 0
        self.storing_nodes = 0
        self.limited = False

class TunnelMeta(object):
    def __init__(self, peer=None, jobs=None):
        assert type(peer) is mnpeer.Peer

        self.peer = peer
        self.queue = None
        self.local_cid = None
        self.jobs = jobs
        self.task_running = False

class VPeer(object):
    def __init__(self, peer=None, path=None, tun_meta=None):
        # self.peer can be a mnpeer.Peer for immediate Peer, or a db.Peer for
        # a non immediate (tunneled) Peer.
        assert type(peer) is Peer or type(peer) is mnpeer.Peer

        self.peer = peer
        self.path = path
        self.tun_meta = tun_meta
        self.used = False
        self.will_store = False
        self.data_present = False

    def __str__(self):
        return\
            "<VPeer: peer.address=[{}], path=[{}]>".format(peer.address, path)

EMPTY_PEER_LIST_MESSAGE = cp.ChordPeerList(peers=[])
EMPTY_PEER_LIST_PACKET = EMPTY_PEER_LIST_MESSAGE.encode()
EMPTY_GET_DATA_MESSAGE = cp.ChordGetData()
EMPTY_GET_DATA_PACKET = EMPTY_GET_DATA_MESSAGE.encode()

class ChordTasks(object):
    def __init__(self, engine):
        self.engine = engine
        self.loop = engine.loop

        self.last_peer_add_time = None
        self.add_peer_memory_cache = {} # {Peer.address, Peer}

    @asyncio.coroutine
    def send_node_info(self, peer):
        log.info("Sending ChordNodeInfo message.")

        local_cid, queue =\
            yield from peer.protocol.open_channel("mpeer", True)
        if not queue:
            return

        msg = cp.ChordNodeInfo()
        msg.sender_address = self.engine.bind_address
        msg.version = self.engine.node.morphis_version

        peer.protocol.write_channel_data(local_cid, msg.encode())

        data = yield from queue.get()
        if not data:
            return

        msg = cp.ChordNodeInfo(data)
        log.info("Received ChordNodeInfo message.")

        peer.version = msg.version
        peer.full_node = True

        yield from peer.protocol.close_channel(local_cid)

        yield from self.engine._check_update_remote_address(msg, peer)

        if log.isEnabledFor(logging.INFO):
            log.info("Outbound Node (addr=[{}]) reports as version=[{}]."\
                .format(peer.address, peer.version))

        self.engine._notify_protocol_ready()

    @asyncio.coroutine
    def perform_stabilize(self):
        found_new_nodes = False

        if not self.engine.peers:
            log.info("No connected nodes, unable to perform stabilize.")
            return

        # Fetch closest to ourselves.
        closest_nodes, new_nodes = yield from\
            self._perform_stabilize(self.engine.node_id, self.engine.peer_trie)

        found_new_nodes |= new_nodes

        closest_found_distance =\
            closest_nodes[0].distance if closest_nodes else None

        # Fetch furthest from ourselves.
        node_id = bytearray(self.engine.node_id)
        for i in range(len(node_id)):
            node_id[i] = (~node_id[i]) & 0xFF

        furthest_nodes, new_nodes = yield from self._perform_stabilize(node_id)

        found_new_nodes |= new_nodes

        if not closest_found_distance:
            closest_found_distance = chord.NODE_ID_BITS
            if furthest_nodes:
                for node in furthest_nodes:
                    if node.distance\
                            and node.distance < closest_found_distance:
                        closest_found_distance = node.distance

            if closest_found_distance is chord.NODE_ID_BITS:
                log.info("Don't know how close a bucket to stop at so not"\
                    " searching inbetween closest and furthest.")
                return

#        closest_found_distance = 0
#        log.warning("Stabilize FindNode id=[{:0512b}]."\
#            .format(int.from_bytes(self.engine.node_id, "big")))

        # Fetch each bucket starting at furthest, stopping when we get to the
        # closest that we found above.
        orig_node_id = self.engine.node_id

        for bit in range(chord.NODE_ID_BITS-1, -1, -1):
            if log.isEnabledFor(logging.INFO):
                log.info("Performing FindNode for bucket [{}]."\
                    .format(bit+1))

            node_id = bytearray(orig_node_id)

            # Change the most significant bit so that the resulting id is
            # inside the bucket for said bit difference.
            byte_ = chord.NODE_ID_BYTES - 1 - (bit >> 3)
            bit_pos = bit % 8
            node_id[byte_] ^= 1 << bit_pos

            # Randomize the remaining less significant bits so that we are
            # performing a FindNode for a random ID within the bucket.
            if bit_pos:
                bit_mask = 1 << (bit_pos - 1)
                bit_mask ^= bit_mask - 1
                node_id[byte_] ^= random.randint(0, 255) & bit_mask

            for i in range(byte_ + 1, chord.NODE_ID_BYTES):
                node_id[i] ^= random.randint(0, 255)

#            log.warning("Stabilize FindNode id=[{:0512b}]."\
#                .format(int.from_bytes(node_id, "big")))

            assert mutil.calc_log_distance(\
                node_id, self.engine.node_id)[0] == (bit + 1),\
                "calc={}, bit={}, diff={}."\
                    .format(\
                        mutil.calc_log_distance(\
                            node_id, self.engine.node_id)[0],\
                        bit + 1,
                        mutil.hex_string(\
                            mutil.calc_raw_distance(\
                                self.engine.node_id, node_id)))

            nodes, new_nodes = yield from self._perform_stabilize(node_id)
            found_new_nodes |= new_nodes

            if not closest_found_distance and not nodes:
                break
            elif bit+1 == closest_found_distance:
                break;

        if new_nodes:
            log.info("Finished total stabilize, checking connections.")
            yield from self.engine.process_connection_count()

    @asyncio.coroutine
    def _perform_stabilize(self, node_id, input_trie=None):
        "returns: conn_nods, new_nodes"\
        "   conn_nodes: found nodes sorted by closets."\
        "   new_nodes: if any found were new."

        conn_nodes = yield from\
            self.send_find_node(node_id, input_trie=input_trie)

        if not conn_nodes:
            return None, False

        for node in conn_nodes:
            # Do not trust hearsay node_id; add_peers will recalculate it from
            # the public key.
            node.node_id = None

        new_nodes = yield from self.engine.add_peers(\
            conn_nodes, process_check_connections=False)

        return conn_nodes, bool(new_nodes)

    @asyncio.coroutine
    def send_get_data(self, data_key, path=None, scan_only=False,\
            retry_factor=1):
        assert type(data_key) in (bytes, bytearray)\
            and len(data_key) == chord.NODE_ID_BYTES,\
            "type(data_key)=[{}], len={}."\
                .format(type(data_key), len(data_key))

        if path:
            if type(path) is str:
                path = path.encode()

            orig_data_key = data_key
            path_hash = enc.generate_ID(path)
            data_key = enc.generate_ID(data_key + path_hash)
        else:
            path_hash = None

        data_id = enc.generate_ID(data_key)

        data_rw = yield from\
            self.send_find_node(data_id, for_data=True, data_key=data_key,\
                path_hash=path_hash, scan_only=scan_only,\
                retry_factor=retry_factor)

        if data_rw.data:
            #FIXME: This is not optimal as we start a whole new FindNode for
            # this. When rewriting this file incorporate this stage into the
            # retrevial process at the end (and have it async just like this).
            r = random.randint(1, 5)
            if retry_factor > 1:
                # Increase chance of uploading a block if it was hard to fetch.
                r = min(r, r * (retry_factor/10))
            if r >= 5:
                if data_rw.version:
                    if log.isEnabledFor(logging.INFO):
                        log.info("Healing updateable key block [{}]."\
                            .format(mbase32.encode(data_key)))

                    sdmsg = cp.ChordStoreData()
                    sdmsg.data = data_rw.data
                    sdmsg.pubkey = data_rw.pubkey
                    sdmsg.path_hash = data_rw.path_hash
                    sdmsg.version = data_rw.version
                    sdmsg.signature = data_rw.signature

                    asyncio.async(\
                        self.send_find_node(\
                            data_id, for_data=True, data_msg=sdmsg),\
                        loop=self.loop)

                    if path:
                        data_key = orig_data_key

                    asyncio.async(\
                        self.send_store_updateable_key_key(\
                            data_rw.pubkey, data_key),\
                        loop=self.loop)
                else:
                    if log.isEnabledFor(logging.INFO):
                        log.info("Healing block [{}]."\
                            .format(mbase32.encode(data_key)))

                    asyncio.async(\
                        self.send_store_data(data_rw.data, store_key=False),\
                        loop=self.loop)

        return data_rw

    @asyncio.coroutine
    def send_get_targeted_data(self, data_key, target_key=None,\
            retry_factor=1):
        assert type(data_key) in (bytes, bytearray)\
            and len(data_key) == chord.NODE_ID_BYTES,\
            "type(data_key)=[{}], len={}."\
                .format(type(data_key), len(data_key))

        data_id = enc.generate_ID(data_key)

        data_rw = yield from\
            self.send_find_node(data_id, for_data=True, data_key=data_key,\
                targeted=True, target_key=target_key,\
                retry_factor=retry_factor)

        return data_rw

    @asyncio.coroutine
    def send_find_key(self, data_key_prefix, significant_bits=None,\
            target_key=None, retry_factor=2):
        assert type(data_key_prefix) in (bytes, bytearray),\
            "type(data_key_prefix)=[{}].".format(type(data_key_prefix))

        if not significant_bits:
            significant_bits = len(data_key_prefix) * 8

        if log.isEnabledFor(logging.INFO):
            log.info("Performing wildcard (key) search (prefix=[{}],"\
                " significant_bits=[{}], target_key=[{}])."\
                    .format(mbase32.encode(data_key_prefix), significant_bits,\
                        mbase32.encode(target_key)))

        ldiff = chord.NODE_ID_BYTES - len(data_key_prefix)
        if ldiff > 0:
            data_key_prefix += b'\x00' * ldiff

        data_rw = yield from\
            self.send_find_node(data_key_prefix,\
                significant_bits=significant_bits, for_data=True,\
                data_key=None, target_key=target_key,\
                retry_factor=retry_factor)

        return data_rw

    @asyncio.coroutine
    def send_store_key(self, data, data_key=None, targeted=False,\
            key_callback=None, retry_factor=5):
        if log.isEnabledFor(logging.INFO):
            data_key_enc = mbase32.encode(data_key) if data_key else None
            log.info("Sending ChordStoreKey for data_key=[{}], targeted=[{}]."\
                .format(data_key_enc, targeted))

        if not data_key:
            data_key = enc.generate_ID(data)
        if key_callback:
            key_callback(data_key)

        skmsg = cp.ChordStoreKey()
        skmsg.data = data
        skmsg.targeted = targeted

        storing_nodes =\
            yield from self.send_find_node(\
                data_key, for_data=True, data_msg=skmsg,\
                retry_factor=retry_factor)

        return storing_nodes

    @asyncio.coroutine
    def send_store_updateable_key_key(\
            self, pubkey, data_key=None, key_callback=None, retry_factor=5):
        assert type(pubkey) in (bytes, bytearray)

        r = yield from\
            self.send_store_key(\
                pubkey, data_key=data_key, key_callback=key_callback,\
                retry_factor=retry_factor)

        return r

    @asyncio.coroutine
    def send_store_data(self, data, store_key=False, key_callback=None,\
            retry_factor=5):
        "Sends a StoreData request, returning the count of nodes that claim"\
        " to have stored it."

        # data_id is a double hash due to the anti-entrapment feature.
        data_key = enc.generate_ID(data)
        if key_callback:
            key_callback(data_key)
        data_id = enc.generate_ID(data_key)

        sdmsg = cp.ChordStoreData()
        sdmsg.data = data

        storing_nodes =\
            yield from self.send_find_node(\
                data_id, for_data=True, data_msg=sdmsg)

        if store_key:
            yield from self.send_store_key(data, data_key)

        return storing_nodes

    @asyncio.coroutine
    def send_store_targeted_data(\
            self, data, store_key=False, key_callback=None, retry_factor=20):
        "Sends a StoreData request for a TargetedBlock, returning the count"\
        " of nodes that claim to have stored it."

        tb_header = data[:tb.TargetedBlock.BLOCK_OFFSET]

        # data_id is a double hash due to the anti-entrapment feature.
        data_key = enc.generate_ID(tb_header)
        if key_callback:
            key_callback(data_key)
        data_id = enc.generate_ID(data_key)

        sdmsg = cp.ChordStoreData()
        sdmsg.data = data
        sdmsg.targeted = True

        storing_nodes =\
            yield from self.send_find_node(\
                data_id, for_data=True, data_msg=sdmsg,\
                retry_factor=retry_factor)

        if store_key:
            yield from self.send_store_key(data, data_key, targeted=True,\
                retry_factor=retry_factor)

        return storing_nodes

    @asyncio.coroutine
    def send_get_synapses(\
            self, target_keys=None, source_key=None, start_timestamp=None,\
            end_timestamp=None, start_key=None, end_key=None, minimum_pow=8,\
            result_callback=None, retry_factor=1):

        req = syn.SynapseRequest()
        if start_timestamp:
            req.start_timestamp = start_timestamp
        if end_timestamp:
            req.end_timestamp = end_timestamp
        if start_key:
            req.start_key = start_key
        if end_key:
            req.end_key = end_key
        if minimum_pow:
            req.minimum_pow = minimum_pow

        all_keys = []

        if target_keys:
            if type(target_keys) in (list, tuple):
                assert not source_key
                keys = []

                for key in target_keys:
                    data_id = enc.generate_ID(key)

                    keys.append(\
                        syn.SynapseRequest.Query(\
                            syn.SynapseRequest.Query.Key(\
                                syn.SynapseRequest.Query.Key.Type.target,\
                                data_id)))

                    all_keys.append((key, data_id))

                query = syn.SynapseRequest.Query(\
                    syn.SynapseRequest.Query.Type.and_,
                    keys)
            elif source_key:
                target_id = enc.generate_ID(target_keys)
                source_id = enc.generate_ID(source_key)

                query = syn.SynapseRequest.Query(
                    syn.SynapseRequest.Query.Type.or_,\
                    [
                        syn.SynapseRequest.Query(\
                            syn.SynapseRequest.Query.Key(\
                                syn.SynapseRequest.Query.Key.Type.target,\
                                target_id)),\
                        syn.SynapseRequest.Query(\
                            syn.SynapseRequest.Query.Key(\
                                syn.SynapseRequest.Query.Key.Type.source,\
                                source_id))])

                all_keys.append((target_keys, target_id))
                all_keys.append((source_key, source_id))
            else:
                target_id = enc.generate_ID(target_keys)

                query = syn.SynapseRequest.Query(\
                    entries=syn.SynapseRequest.Query.Key(\
                        syn.SynapseRequest.Query.Key.Type.target,\
                        target_id))

                all_keys.append((target_keys, target_id))
        else:
            source_id = enc.generate_ID(source_key)

            query = syn.SynapseRequest.Query(\
                syn.SynapseRequest.Query.Key(\
                    syn.SynapseRequest.Query.Key.Type.source,\
                    source_id))

            all_keys.append((source_key, source_id))

        req.query = query

        total = []

        while True:
            r = yield from self._send_get_synapses(\
                req, all_keys, result_callback, retry_factor)

            if not r:
                return total if total else None

            if result_callback:
                yield from result_callback(r)

            if not r.limited:
                if not total:
                    return r

                total.extend(r.data)
                return total

            total.extend(r.data)
            req.start_key = mutil.bit_add(r.data[-1].synapse_key, 1)

    @asyncio.coroutine
    def _send_get_synapses(self, synapse_request, all_keys, result_callback,\
            retry_factor):
        data_key = all_keys[0][0] if type(all_keys[0][0]) is bytes\
            else bytes(all_keys[0][0])

        tasks = []

        for key in all_keys:
            tasks.append(self.send_find_node(\
                key[1], for_data=True, data_key=data_key,\
                synapse_request=synapse_request, retry_factor=retry_factor))

        data_rw = None

        while True:
            done, pending = yield from asyncio.wait(\
                tasks, loop=self.loop, return_when=futures.FIRST_COMPLETED)

            for ele in done:
                data_rw = ele.result()
                if data_rw.data:
                    for running in pending:
                        running.cancel()
                    return data_rw

            if not pending:
                return None

            tasks = list(pending)

    @asyncio.coroutine
    def send_store_synapse(\
            self, synapse, store_key=True, key_callback=None, retry_factor=20):
        "Sends a StoreData request for a Synapse, returning the count of"\
        " nodes that claim to have stored it."
        assert type(synapse) is syn.Synapse

        data = synapse.buf if synapse.buf else (yield from synapse.encode())

        if log.isEnabledFor(logging.INFO):
            if synapse.synapse_pow:
                thepow = mbase32.encode(synapse.synapse_pow)
            else:
                thepow = "<NONE>"

            log.info(\
                "Sending Store{{Data/Key}} for Synapse (synapse_key=[{}],"\
                    " synapse_pow=[{}], target_key=[{}], source_key=[{}])."\
                        .format(\
                            mbase32.encode(synapse.synapse_key),
                            thepow,
                            mbase32.encode(synapse.target_key),
                            mbase32.encode(synapse.source_key)))

        if key_callback:
            key_callback(synapse.synapse_key)

        sdmsg = cp.ChordStoreData()
        sdmsg.data = data
        sdmsg.targeted = True

        #NOTE: We use the hashes of the keys as the IDs (DHT Key) due to the
        # DHT anti-entrapment feature.

        # Store for synapse_key (natural key of synapse).
        storing_nodes =\
            yield from self.send_find_node(\
                enc.generate_ID(synapse.synapse_key), for_data=True,
                data_msg=sdmsg, retry_factor=retry_factor)

        if synapse.nonce:
            # Store for synapse_pow (PoW key of synapse).
            storing_nodes +=\
                yield from self.send_find_node(\
                    enc.generate_ID(synapse.synapse_pow), for_data=True,
                    data_msg=sdmsg, retry_factor=retry_factor)
            if store_key:
                yield from self.send_store_key(\
                    data, synapse.synapse_pow, targeted=True,\
                    retry_factor=retry_factor)

        # Store for target_key.
        for target_key in synapse.target_keys:
            storing_nodes +=\
                yield from self.send_find_node(\
                    enc.generate_ID(target_key), for_data=True,
                    data_msg=sdmsg, retry_factor=retry_factor)

        # Store for source_key.
        storing_nodes +=\
            yield from self.send_find_node(\
                enc.generate_ID(synapse.source_key), for_data=True,
                data_msg=sdmsg, retry_factor=retry_factor)

        # Store the synapse_key itself (for find_key operations).
        if store_key:
            yield from self.send_store_key(\
                data, synapse.synapse_key, targeted=True,\
                retry_factor=retry_factor)

        return storing_nodes

    @asyncio.coroutine
    def send_store_updateable_key(\
            self, data, privatekey, path=None, version=None, store_key=None,\
            key_callback=None, retry_factor=5):
        assert not path or type(path) is bytes, type(path)
        assert not version or type(version) is int, type(version)

        public_key_bytes = privatekey.asbytes() # asbytes=public key.

        data_key = enc.generate_ID(public_key_bytes)

        if key_callback:
            key_callback(data_key)

        if path:
            path_hash = enc.generate_ID(path)
            data_id = enc.generate_ID(enc.generate_ID(data_key + path_hash))
        else:
            path_hash = b""
            data_id = enc.generate_ID(data_key)

        if log.isEnabledFor(logging.DEBUG):
            log.debug("data_key=[{}], data_id=[{}]."\
                .format(mbase32.encode(data_key), mbase32.encode(data_id)))

        hm = bytearray()
        hm += sshtype.encodeBinary(path_hash)
        hm += sshtype.encodeMpint(version)
        hm += sshtype.encodeBinary(enc.generate_ID(data))

        signature = privatekey.sign_ssh_data(hm)

        sdmsg = cp.ChordStoreData()
        sdmsg.data = data
        sdmsg.pubkey = public_key_bytes
        sdmsg.path_hash = path_hash
        sdmsg.version = version
        sdmsg.signature = signature

        storing_nodes =\
            yield from self.send_find_node(\
                data_id, for_data=True, data_msg=sdmsg)

        if store_key:
            yield from self.send_store_updateable_key_key(\
                public_key_bytes, data_key)

        return storing_nodes

    @asyncio.coroutine
    def send_find_node(self, node_id, significant_bits=None, input_trie=None,\
            for_data=False, data_msg=None, data_key=None, path_hash=None,\
            targeted=False, target_key=None, scan_only=False,\
            synapse_request=None, retry_factor=1):
        "Returns found nodes sorted by closets. If for_data is True then"\
        " this is really {get/store}_data instead of find_node. If data_msg"\
        " is None than it is get_data and the data is returned. Store data"\
        " currently returns the count of nodes that claim to have stored the"\
        " data."

        #NOTE: I think targeted parameter is only for fetches.

        assert len(node_id) == chord.NODE_ID_BYTES
        # data_key needs to be bytes for PyCrypto usage later on.
        assert data_key is None or type(data_key) is bytes, type(data_key)

        if for_data:
            data_mode = cp.DataMode.get if data_msg is None\
                else cp.DataMode.store
        else:
            data_mode = cp.DataMode.none

        if not self.engine.peers:
            log.info("No connected nodes, unable to send FindNode.")
            return self._generate_fail_response(data_mode, data_key)

        if not input_trie:
            input_trie = bittrie.BitTrie()
#            for peer in self.engine.peer_trie:
            for peer in self.engine.peers.values():
                if not peer.full_node:
                    continue
                key = bittrie.XorKey(node_id, peer.node_id)
                input_trie[key] = peer

        max_initial_queries = 3
        slowpoke_factor = 2
        max_concurrent_queries = max_initial_queries * slowpoke_factor

        maximum_depth = 512

        if log.isEnabledFor(logging.INFO):
            log.info("Performing FindNode (node_id=[{}], data_mode={}) to a"\
                " max depth of [{}]."\
                    .format(mbase32.encode(node_id), data_mode, maximum_depth))

        result_trie = bittrie.BitTrie()

        # Store ourselves to ignore when peers respond with us in their list.
        result_trie[bittrie.XorKey(node_id, self.engine.node_id)] = False

        tasks = []
        used_tunnels = {}
        far_peers_by_path = {}

        data_msg_type = type(data_msg)

        # Build the FindNode message that we are going to send.
        fnmsg = cp.ChordFindNode()
        fnmsg.node_id = node_id
        fnmsg.data_mode = data_mode
        if data_msg_type is cp.ChordStoreData:
            fnmsg.version = data_msg.version
        if significant_bits:
            fnmsg.significant_bits = significant_bits
            if target_key:
                fnmsg.target_key = target_key
        if synapse_request:
            fnmsg.query = synapse_request
        fnmsg.encode() # Later thing expect fnmsg.buf to be ready.

        # Setup the DataResponseWrapper which is returned from this function
        # but also is used to pass around some info to helper functions this
        # main send_find_node(..) function calls.
        sent_data_request = Counter(0)
        data_rw = DataResponseWrapper(data_key)
        if data_msg_type is cp.ChordStoreData:
            if data_msg.pubkey:
                data_rw.pubkey = data_msg.pubkey
            if data_msg.path_hash:
                data_rw.path_hash = data_msg.path_hash
        else:
            if path_hash:
                data_rw.path_hash = path_hash
            if targeted:
                data_rw.targeted = True
                data_rw.target_key = target_key

        #######################################################################
        # Open the tunnels with upto max_initial_queries immediate PeerS.
        for peer in input_trie:
            key = bittrie.XorKey(node_id, peer.node_id)
            vpeer = VPeer(peer)
            # Store immediate PeerS in the result_trie.
            result_trie[key] = vpeer

            if len(tasks) == max_initial_queries:
                # We still add all immediate PeerS so that later we can ignore
                # them if they are included in lists returned by querying.
                continue
            if not peer.ready():
                continue

            tun_meta = TunnelMeta(peer)
            used_tunnels[vpeer] = tun_meta

            tasks.append(self._send_find_node(\
                vpeer, fnmsg, result_trie, tun_meta, data_mode,\
                far_peers_by_path, data_rw))

            vpeer.used = True

        if not tasks:
            log.info("Cannot perform FindNode, as we know no closer nodes.")
            return self._generate_fail_response(data_mode, data_key)

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Starting {} root level FindNode tasks."\
                .format(len(tasks)))

        done_cnt = 0
        max_time = 7.0 #TODO: This is probably excessive!
        diff = 0
        start = datetime.today()
        while diff < max_time and done_cnt < max_initial_queries:
            try:
                done, pending =\
                    yield from asyncio.wait(\
                        tasks,\
                        loop=self.loop,\
                        timeout=max_time - diff,\
                        return_when=futures.FIRST_COMPLETED)
            except asyncio.CancelledError:
                self._close_channels(used_tunnels)
                raise

            done_cnt += len(done)
            tasks = list(pending)

            if not pending:
                break

            diff = (datetime.today() - start).total_seconds()

        if not done_cnt:
            log.info("Couldn't open any tunnels in time, giving up.")
            for task in tasks:
                task.cancel()
            self._close_channels(used_tunnels)
            return self._generate_fail_response(data_mode, data_key)

        #######################################################################
        # Instruct our tunnels to relay the FindNode message out further, also
        # processing the responses and using that data to build further tunnels
        # and send out the FindNode even deeper. After this loop, we have
        # done all the finding we are going to do.
        query_cntr = Counter(0)
        task_cntr = Counter(0)
        depth = Counter(0)
        done_all = asyncio.Event(loop=self.loop)
        done_one = asyncio.Event(loop=self.loop)

        wanted = 1 if data_mode is cp.DataMode.get else max_initial_queries
        if retry_factor > 1:
            wanted = min(wanted, wanted + 1 * (retry_factor/10))

        for depth.value in range(1, maximum_depth):
            if data_rw.data_present_cnt >= wanted:
                break;
            if data_rw.will_store_cnt >= wanted:
                break;

            direct_peers_lower = 0
            current_depth_step_query_cnt = 0
            for row in result_trie:
                if row is False:
                    # Row is ourself. Prevent infinite loops.
                    # Sometimes we are looking closer than ourselves, sometimes
                    # further (stabilize vs other). We could use this to end
                    # the loop maybe, do checks. For now, just ignoring it to
                    # prevent infinite loops.
                    continue

                if row.used:
                    # We've already sent to this Peer.
                    continue

                if row.path is None:
                    # This is a immediate (direct connected) Peer.
                    peer = row.peer

                    if not peer.ready():
                        continue

                    tun_meta = TunnelMeta(peer)
                    used_tunnels[row] = tun_meta

                    query_cntr.value += 1

                    task = asyncio.async(\
                        self._send_find_node(\
                            row, fnmsg, result_trie, tun_meta, data_mode,\
                            far_peers_by_path, data_rw, done_one=done_one,\
                            done_all=done_all, query_cntr=query_cntr),\
                        loop=self.loop)

                    tasks.append(task)

                    row.used = True

                    current_depth_step_query_cnt += 1
                    continue

                tun_meta = row.tun_meta
                if not tun_meta.queue:
                    # The tunnel is not open to this Peer anymore.
                    continue

                if log.isEnabledFor(logging.DEBUG):
                    log.debug("Sending FindNode to path [{}]."\
                        .format(row.path))

                pkt = self._generate_relay_packets(row.path)

                tun_meta.peer.protocol.write_channel_data(\
                    tun_meta.local_cid, pkt)

                row.used = True
                query_cntr.value += 1
                current_depth_step_query_cnt += 1

                if tun_meta.jobs is None:
                    # If this is the first relay for this tunnel, then start a
                    # _process_find_node_relay task for that tunnel.
                    tun_meta.jobs = 1
                    task_cntr.value += 1
                    task = asyncio.async(\
                        self._process_find_node_relay(\
                            node_id, significant_bits, tun_meta, query_cntr,\
                            done_all, done_one, task_cntr, result_trie,\
                            data_mode, far_peers_by_path, sent_data_request,\
                            synapse_request, data_rw, depth),\
                        loop=self.loop)
                    tasks.append(task)
                else:
                    tun_meta.jobs += 1

#                if query_cntr.value == max_concurrent_queries:
                if current_depth_step_query_cnt == max_concurrent_queries:
                    break

            if not current_depth_step_query_cnt:
                log.info("FindNode search has ended at closest nodes.")
                break

#            yield from done_all.wait()
#            done_all.clear()
            # Wait upto a second for at least one response.
            try:
                try:
                    yield from asyncio.wait_for(\
                        done_one.wait(),\
                        timeout=1,\
                        loop=self.loop)
                except asyncio.TimeoutError:
                    pass

                done_one.clear()

                # Wait a bit more for the rest of the tasks.
                try:
                    yield from asyncio.wait_for(\
                        done_all.wait(),\
                        timeout=0.1 * retry_factor,\
                        loop=self.loop)
                except asyncio.TimeoutError:
                    pass

                done_all.clear()
            except asyncio.CancelledError:
                self._close_channels(used_tunnels)
                for task in tasks:
                    task.cancel()
                raise

#            assert query_cntr.value == 0

            if not task_cntr.value:
                log.info("All tasks (tunnels) exited.")
                break

        #######################################################################
        # Proceed to the second stage of the request.
        # FIXME: Write this whole stuff to merge these two so it can be async.
        if data_mode.value and not scan_only:
            stores_sent = 0

            if data_mode is cp.DataMode.get:
                msg_name = "GetData"

                data_rw.data_done = asyncio.Event(loop=self.loop)

                if significant_bits:
                    closest_datas = []

                    #FIXME: Ahh! If we have it why did we do the above! :)
                    # Move this up to the top and save us a send_find_node!
                    data_present = yield from self._check_has_data(\
                        node_id, significant_bits, target_key, synapse_request)
                    #NOTE: Regarding FIXME above: we didn't 'have' it, we have
                    # something close, but we want closest we can find overall,
                    # so we don't even care what we have until after we see
                    # what the network has because we then are only interested
                    # in the closest. (Something like that is the answer to the
                    # above FIXME question).

                    #NOTE: For significant_bits not None, data_present return
                    # value is a key -- not boolean.

                    if data_present:
                        closest_datas.append(data_present)

                    #TODO: This could be optimized to be built as peers sent
                    # the present message instead of iterating the whole list.
                    for vpeer in result_trie:
                        if not vpeer:
                            continue
                        if vpeer.data_present:
                            closest_datas.append(vpeer.data_present)

                    closest_datas.sort()

                    if len(closest_datas):
                        data_rw.data_key = closest_datas[0]

                    result_trie = []
            else:
                assert data_mode is cp.DataMode.store

                if data_msg_type is cp.ChordStoreData:
                    msg_name = "StoreData"
                else:
                    assert data_msg_type is cp.ChordStoreKey
                    msg_name = "StoreKey"

                data_msg_pkt = data_msg.encode()

            # If in get_data mode, then send a GetData message to each Peer
            # that indicated data presence, one at a time, stopping upon first
            # success. Right now we will start at closest node, which might
            # make it harder to Sybil attack targeted data_ids.
            #TODO: Figure out if that is so, because otherwise we might not
            # want to grab from the closest for load balancing purposes.
            # Certainly future versions should have a more advanced algorithm
            # here that bases the decision on latency, tunnel depth, trust,
            # Etc.

            # If in store_data mode, then send the data to the closest willing
            # nodes that we found.

            if log.isEnabledFor(logging.INFO):
                log.info("Sending {} with {} tunnels still open."\
                    .format(msg_name, task_cntr.value))

            # Just FYI: There might be no tunnels open if we are connected to
            # everyone, or only immediate PeerS were closest.

            sent_data_request.value = 1 # Let tunnel process tasks know.

            # We have to process responses from three different cases:
            # 1. Peer reached through a tunnel.
            # 2. Immediate Peer that is also an open tunnel. (task running)
            # 3. Immediate Peer that is not an open tunnel.
            # The last case requires a new processing task as no task is
            # already running to handle it. Case 1 & 2 are handled by the
            # _process_find_node_relay(..) co-routine tasks. The last case can
            # only happen if there was no tunnel opened with that Peer. If the
            # tunnel got closed then we don't even use that immediate Peer so
            # it being closed won't be a case we have to handle. (We don't
            # reopen channels at this point.)

            #NOTE: result_trie is [] when significant_bits.

            done_one.clear()

            for row in result_trie:
                if row is False:
                    # Row is ourself.
                    if data_mode is cp.DataMode.get:
                        assert significant_bits is None

                        data_present =\
                            yield from self._check_has_data(\
                                node_id, None, None, synapse_request)

                        if not data_present:
                            continue

                        r = yield from self._process_own_data(\
                            node_id, data_rw, synapse_request)

                        if not r:
                            # Data was invalid somehow!
                            log.warning("Data from ourselves was invalid!")
                            continue

                        # Otherwise, break out of the loop as we've fetched the
                        # data.
                        break
                    else:
                        assert data_mode is cp.DataMode.store

                        will_store, need_pruning =\
                            yield from self._check_do_want_data(\
                                node_id, fnmsg.version)

                        if not will_store:
                            continue

                        log.info("We are choosing to additionally store the"\
                            " data locally.")

                        if data_msg_type is cp.ChordStoreData:
                            if data_msg.targeted and data_msg.data[:16]\
                                    != MorphisBlock.UUID:
                                r = yield from self._store_synapse(\
                                    None, node_id, data_msg, need_pruning)
                            else:
                                r = yield from self._store_data(\
                                    None, node_id, data_msg, need_pruning)
                        else:
                            assert data_msg_type is cp.ChordStoreKey

                            r = yield from\
                                self._store_key(peer, fnmsg.node_id, data_msg)

                        if not r:
                            log.info("We failed to store the data.")

                        #NOTE: We don't count ourselves in storing_nodes.

                        # Store it still elsewhere if others want it as well.
                        continue

                if data_mode is cp.DataMode.get:
                    if not row.data_present:
                        # This node doesn't have our data.
                        continue
                else:
                    assert data_mode is cp.DataMode.store

                    if not row.will_store:
                        # The node may be close to id, but it says that it
                        # does not want to store the proposed data for whatever
                        # reason.
                        continue

                tun_meta = row.tun_meta
                if tun_meta and not tun_meta.queue:
                    # Peer is reached through a tunnel, but the tunnel is
                    # closed.
                    continue

                if log.isEnabledFor(logging.INFO):
                    log.info("Sending {} to Peer [{}] and path [{}]."\
                        .format(msg_name, row.peer.address, row.path))

                if data_mode is cp.DataMode.get:
                    pkt = EMPTY_GET_DATA_PACKET
                else:
                    assert data_mode is cp.DataMode.store
                    pkt = data_msg_pkt

                if tun_meta:
                    # Then this is a Peer reached through a tunnel.
                    pkt = self._generate_relay_packets(row.path, pkt)
                    tun_meta.jobs += 1
                else:
                    # Then this is an immediate Peer.
                    tun_meta = used_tunnels.get(row)

                    if tun_meta.task_running:
                        # Then this immediate Peer is an open tunnel and will
                        # be handled as described above for case #2.
                        tun_meta.jobs += 1
                    elif tun_meta.queue:
                        # Then this immediate Peer is not an open tunnel and we
                        # will have to start a task to process its DataStored
                        # message.
                        if tun_meta.jobs is None:
                            tun_meta.jobs = 1
                        else:
                            tun_meta.jobs += 1

                        asyncio.async(\
                            self._wait_for_data_stored(\
                                data_mode, row, tun_meta, synapse_request,\
                                query_cntr, done_one, done_all, data_rw),\
                            loop=self.loop)
                    else:
                        # Then this immediate Peer had its channel closed;
                        # don't use it.
                        continue

                tun_meta.peer.protocol.write_channel_data(\
                    tun_meta.local_cid, pkt)

                query_cntr.value += 1
                done_all.clear()

                if data_mode is cp.DataMode.get:
                    # We only send one at a time, stopping at success.
#                    yield from done_all.wait()
#                    done_all.clear()
                    try:
                        yield from\
                            asyncio.wait_for(\
                                data_rw.data_done.wait(),\
                                1 + (retry_factor/10))
                        data_rw.data_done.clear()
                    except asyncio.TimeoutError:
                        log.info("Timeout waiting for data block.")
                        pass

                    if data_rw.data is not None: # Handle the 'blank data' blk.
                        # If the data was read and validated successfully, then
                        # break out of the loop and clean up.
                        break
                    else:
                        # If the data was not validated correctly, then we ask
                        # the next Peer.
                        continue
                else:
                    assert data_mode is cp.DataMode.store

                    stores_sent += 1
                    if stores_sent == max_initial_queries:
                        break

            if data_mode is cp.DataMode.store:
                try:
                    yield from asyncio.wait_for(\
                        done_one.wait(),\
                        timeout=1,\
                        loop=self.loop)
                except asyncio.TimeoutError:
                    pass

                done_one.clear()

                # Wait a bit more for the rest of the tasks.
                try:
                    yield from asyncio.wait_for(\
                        done_all.wait(),\
                        timeout=0.1 * retry_factor,\
                        loop=self.loop)
                except asyncio.TimeoutError:
                    pass

                if log.isEnabledFor(logging.INFO):
                    log.info("Sent StoreData to [{}/{}] tried nodes."\
                        .format(data_rw.storing_nodes, stores_sent))

#            if query_cntr.value:
#                # query_cntr can be zero if no PeerS were tried.
#                yield from done_all.wait()
#                done_all.clear()
#
#            assert query_cntr.value == 0, query_cntr.value

            if log.isEnabledFor(logging.INFO):
                log.info("Finished waiting for {} operations; now"\
                    " cleaning up.".format(msg_name))

        if scan_only:
            try:
                yield from asyncio.wait_for(\
                    done_all.wait(),\
                    timeout=0.1 * retry_factor,\
                    loop=self.loop)
            except asyncio.TimeoutError:
                pass

        #######################################################################
        # Close everything now that we are done.
        for task in tasks:
            task.cancel()
        tasks.clear()
        self._close_channels(used_tunnels)
#        yield from asyncio.wait(tasks, loop=self.loop)

        if data_mode.value:
            asyncio.async(\
                self._possibly_add_peers(result_trie), loop=self.loop)

            if data_mode is cp.DataMode.store:
                assert data_rw.storing_nodes >= 0
                return data_rw.storing_nodes
            else:
                assert data_mode is cp.DataMode.get

                if not significant_bits and data_rw.data is None:
                    # Give one last try to find locally. I think we don't
                    # check locally always?
                    data_present = yield from self._check_has_data(\
                        node_id, significant_bits, target_key, synapse_request)

                    if data_present:
                        log.warning("FOUND LOCALLY AFTER PROOF TRIGGERD.")
                        data_rw.data_done = asyncio.Event(loop=self.loop)
                        yield from self._process_own_data(\
                            node_id, data_rw, synapse_request)

                if data_rw.data is None\
                        and (not significant_bits or not data_rw.data_key):
                    log.info("Failed to find the data!")
                else:
                    if data_rw.version is not None:
                        if log.isEnabledFor(logging.INFO):
                            log.info("Found updateable key data;"\
                                " version=[{}].".format(data_rw.version))

                return data_rw

        rnodes = [vpeer.peer for vpeer in result_trie if vpeer and vpeer.path]

        if log.isEnabledFor(logging.INFO):
            for vpeer in result_trie:
                if not vpeer or not vpeer.path:
                    continue
                log.info("Found closer Peer (address={})."\
                    .format(vpeer.peer.address))

        if log.isEnabledFor(logging.INFO):
            log.info("FindNode found [{}] Peers.".format(len(rnodes)))

        return rnodes

    @asyncio.coroutine
    def _possibly_add_peers(self, result_trie):
        only_memory = False

        if self.last_peer_add_time:
            diff = datetime.today() - self.last_peer_add_time

            if diff.total_seconds() < 1:
                return

            if diff.total_seconds() < 15:
                only_memory = True

        self.last_peer_add_time = datetime.today()

        conn_nodes = self.add_peer_memory_cache

        for vpeer in result_trie:
            if not vpeer or not vpeer.path:
                continue

            node = vpeer.peer

            # Do not trust hearsay node_id; add_peers will recalculate it from
            # the public key.
            node.node_id = None

            conn_nodes.setdefault(node.address, node)

        if only_memory:
            return

        log.info("Adding noticed PeerS to the database.")

        new_nodes = yield from self.engine.add_peers(\
            conn_nodes.values(), process_check_connections=False)

        conn_nodes.clear()

    def _close_channels(self, used_tunnels):
        for tun_meta in used_tunnels.values():
            asyncio.async(\
                tun_meta.peer.protocol.close_channel(tun_meta.local_cid),\
                loop=self.loop)

    def _generate_fail_response(self, data_mode, data_key):
        if data_mode.value:
            if data_mode is cp.DataMode.store:
                return 0
            else:
                assert data_mode is cp.DataMode.get
                return DataResponseWrapper(data_key)
        else:
            return 0

    def _generate_relay_packets(self, path, payload=None):
        "path: list of indexes."\
        "payload_msg: optional packet data to wrap."

        #TODO: MAYBE: replace embedded ChordRelay packets with
        # just one that has a 'path' field. Just more simple,
        # efficient and should be easy change. It means less work
        # for intermediate nodes that may want to examine the deepest
        # packet, in the case of data, in order to opportunistically
        # store the data. This might be a less good solution for
        # anonyminty, but it could be as easilty switched back if that
        # is true and a priority.

        #TODO: ChordRelay should be modified to allow a message payload instead
        # of the byte 'packet' payload. This way it can recursively call
        # encode() on the payloads that way appending data each iteration
        # instead of the inefficient way it does it now with inserting the
        # wrapping packet each iteration. This is an especially important
        # improvement now that a huge data packet is tacked on the end.

        pkt = None
        for idx in reversed(path):
            msg = cp.ChordRelay()
            msg.index = idx
            if pkt:
                msg.packets = [pkt]
            else:
                if payload:
                    msg.packets = [payload]
                else:
                    msg.packets = []
            pkt = msg.encode()

        return pkt

    @asyncio.coroutine
    def _send_find_node(self, vpeer, fnmsg, result_trie, tun_meta,\
            data_mode, far_peers_by_path, data_rw, done_all=None,\
            done_one=None, query_cntr=None):
        "Opens a channel and sends a 'root level' FIND_NODE to the passed"\
        " connected peer, adding results to the passed result_trie, and then"\
        " exiting. The channel is left open so that the caller may route to"\
        " those results through this 'root level' FIND_NODE peer."

        peer = vpeer.peer

        try:
            local_cid, queue =\
                yield from asyncio.wait_for(\
                    peer.protocol.open_channel("mpeer", True),\
                    timeout=60,\
                    loop=self.loop)
        except asyncio.TimeoutError:
            if log.isEnabledFor(logging.INFO):
                log.info("Timeout opening channel to Peer (dbid=[{}])."\
                    .format(peer.dbid))
            peer.protocol.close()
            queue = None

        if not queue:
            if self.engine.node.tormode:
                if not peer.protocol.closed():
                    if log.isEnabledFor(logging.INFO):
                        log.info("Closing stalled connection to Peer"\
                            " (dbid=[{}])."\
                                .format(peer.dbid))
                    peer.protocol.close()

            if query_cntr:
                query_cntr.value -= 1
                done_one.set()
                if query_cntr.value == 0:
                    done_all.set
            return

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Sending root level FindNode msg to Peer (dbid=[{}])."\
                .format(peer.dbid))

        assert fnmsg.buf
        peer.protocol.write_channel_data(local_cid, fnmsg.buf)

        pkt = yield from queue.get()
        if not pkt:
            if query_cntr:
                query_cntr.value -= 1
                done_one.set()
                if query_cntr.value == 0:
                    done_all.set
            return

        tun_meta.queue = queue
        tun_meta.local_cid = local_cid

        if data_mode.value:
            if data_mode is cp.DataMode.store:
                msg = cp.ChordStorageInterest(pkt)

                if log.isEnabledFor(logging.INFO):
                    log.info("Peer (dbid=[{}]) said will_store=[{}]."\
                        .format(vpeer.peer.dbid, msg.will_store))

                vpeer.will_store = msg.will_store

                if msg.will_store:
                    data_rw.will_store_cnt += 1
            elif data_mode is cp.DataMode.get:
                msg = cp.ChordDataPresence(pkt)

                if log.isEnabledFor(logging.INFO):
                    log.info("Peer (dbid=[{}]) said data_present=[{}],"\
                        " first_id=[{}]."\
                            .format(vpeer.peer.dbid, msg.data_present,\
                                mbase32.encode(msg.first_id)))

                if fnmsg.significant_bits:
                    data_present = msg.first_id
                else:
                    data_present = msg.data_present

                if data_present:
                    data_rw.data_present_cnt += 1

                vpeer.data_present = data_present
            else:
                assert False

            pkt = yield from queue.get()
            if not pkt:
                if query_cntr:
                    query_cntr.value -= 1
                    done_one.set()
                    if query_cntr.value == 0:
                        done_all.set
                return

        msg = cp.ChordPeerList(pkt)

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Root level FindNode to Peer (id=[{}]) returned {}"\
                " PeerS.".format(peer.dbid, len(msg.peers)))

        node_id = fnmsg.node_id

        idx = 0
        for rpeer in msg.peers:
            if log.isEnabledFor(logging.DEBUG):
                log.debug("Peer (dbid=[{}]) returned PeerList containing Peer"\
                    " (address=[{}]).".format(peer.dbid, rpeer.address))

            tvpeer = VPeer(rpeer, [idx], tun_meta)

            key = bittrie.XorKey(node_id, rpeer.node_id)
            result_trie.setdefault(key, tvpeer)
            if data_mode.value:
                far_peers_by_path.setdefault((peer.dbid, idx), tvpeer)

            idx += 1

        if query_cntr:
            query_cntr.value -= 1
            done_one.set()
            if query_cntr.value == 0:
                done_all.set

    @asyncio.coroutine
    def _process_find_node_relay(\
            self, node_id, significant_bits, tun_meta, query_cntr, done_all,\
            done_one, task_cntr, result_trie, data_mode, far_peers_by_path,\
            sent_data_request, sreq, data_rw, depth):
        "This method processes an open tunnel's responses, processing the"\
        " incoming messages and appending the PeerS in those messages to the"\
        " result_trie. This method does not close any channel to the tunnel,"\
        " and does not stop processing and exit until the channel is closed"\
        " either by the Peer or by our side outside this method."

        assert type(sent_data_request) is Counter

        tun_meta.task_running = True

        try:
            r = yield from self.__process_find_node_relay(\
                node_id, significant_bits, tun_meta, query_cntr, done_all,\
                done_one, task_cntr, result_trie, data_mode,\
                far_peers_by_path, sent_data_request, sreq, data_rw, depth)

            if not r:
                return
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("__process_find_node_relay(..)")

        if tun_meta.jobs:
            # This tunnel closed while there were still pending jobs, so
            # consider those jobs now completed and subtract them from the
            # count of ongoing jobs.
            query_cntr.value -= tun_meta.jobs
            if not query_cntr.value:
                done_one.set() # Ensure to wakeup waiter since all is closed.
                done_all.set()
            tun_meta.jobs = 0

        # Mark tunnel as closed.
        tun_meta.queue = None
        tun_meta.task_running = False
        # Update counter of open tunnels.
        task_cntr.value -= 1

    @asyncio.coroutine
    def __process_find_node_relay(\
            self, node_id, significant_bits, tun_meta, query_cntr, done_all,\
            done_one, task_cntr, result_trie, data_mode, far_peers_by_path,\
            sent_data_request, sreq, data_rw, depth):
        "Inner function for above call."
        while True:
            pkt = yield from tun_meta.queue.get()
            if not pkt:
                break

            if sent_data_request.value\
                    and cp.ChordMessage.parse_type(pkt) != cp.CHORD_MSG_RELAY:
                # This co-routine only expects unwrapped packets in the case
                # we have sent data and are waiting for an ack from the
                # immediate Peer.
                pkts = (pkt,)
                path = None
            else:
                if log.isEnabledFor(logging.DEBUG):
                    log.debug("Unwrapping ChordRelay packet.")
                pkts, path = self.unwrap_relay_packets(pkt, data_mode)
                path = tuple(path)

            pkt_type = cp.ChordMessage.parse_type(pkts[0])

            if data_mode.value and pkt_type != cp.CHORD_MSG_PEER_LIST:
                # Above pkt_type check is because a node that had no closer
                # PeerS for us and didn't have or want data will have closed
                # the channel and thus caused only an empty PeerList to be
                # sent to us.
                if sent_data_request.value:
                    if data_mode is cp.DataMode.get:
                        if pkt_type != cp.CHORD_MSG_DATA_RESPONSE:
                            # They are too late! We are only looking for
                            # DataResponse messages now.
                            continue

                        try:
                            rmsg = cp.ChordDataResponse(pkts[0])

                            r = yield from self._process_data_response(\
                                sreq, rmsg, tun_meta, path, data_rw)
                        except Exception:
                            r = None
                            if log.isEnabledFor(logging.INFO):
                                log.info(\
                                    "Peer [{}] sent corrupt"\
                                    " ChordDataResponse with [path={}]."\
                                        .format(\
                                            tun_meta.peer.address,\
                                            path))

                        if not r:
                            # If the data was invalid, we will try from another
                            # Peer (or possibly tunnel).
                            log.info("Data in response did not match request"\
                                " key.")

                            query_cntr.value -= 1
                            # There should only be one GetData at a time.
                            assert not query_cntr.value, query_cntr.value
                            done_one.set()
                            done_all.set()
                            continue
                    else:
                        assert data_mode is cp.DataMode.store

                        if pkt_type != cp.CHORD_MSG_DATA_STORED:
                            # They are too late! We are only looking for
                            # DataStored messages now.
                            continue
                        else:
                            store_msg = cp.ChordDataStored(pkts[0])
                            if log.isEnabledFor(logging.DEBUG):
                                log.debug("Received DataStored (stored=[{}])"\
                                    " message from Peer (dbid={})."\
                                        .format(store_msg.stored,\
                                            tun_meta.peer.dbid, path))

                            if store_msg.stored:
                                data_rw.storing_nodes += 1

                    query_cntr.value -= 1
                    done_one.set()
                    if not query_cntr.value:
                        done_all.set()
#                        return False

                    continue

                if data_mode is cp.DataMode.get:
                    pmsg = cp.ChordDataPresence(pkts[0])

                    if log.isEnabledFor(logging.INFO):
                        log.info("Peer (dbid=[??]) said data_present=[{}],"\
                            " first_id=[{}]."\
                                .format(pmsg.data_present,\
                                    mbase32.encode(pmsg.first_id)))

                    if significant_bits:
                        data_present = pmsg.first_id
                    else:
                        data_present = pmsg.data_present

                    if data_present:
                        data_rw.data_present_cnt += 1

                        apath = (tun_meta.peer.dbid,) + path
                        rvpeer = far_peers_by_path.get(apath)
                        if rvpeer is None:
                            #FIXME: Treat this as attack, Etc.
                            log.warning("Far node not found in dict for apath"\
                                "[{}].".format(apath))
                        else:
                            if significant_bits:
                                rvpeer.data_present = pmsg.first_id
                            else:
                                assert pmsg.data_present
                                rvpeer.data_present = True

                    if len(pkts) == 1:
                        # If a node has no closer peers, it may close channel
                        # after sending the DataPresence message instead of
                        # also sending a PeerList.
                        tun_meta.jobs -= 1
                        query_cntr.value -= 1
                        if not query_cntr.value:
                            done_one.set()
                            done_all.set()
                        elif len(path) == depth.value:
                            done_one.set()
                        continue
                else:
                    assert data_mode is cp.DataMode.store

                    imsg = cp.ChordStorageInterest(pkts[0])

                    if log.isEnabledFor(logging.INFO):
                        log.info("Peer (path=[??]) said will_store=[{}]."\
                            .format(imsg.will_store))

                    if imsg.will_store:
                        apath = (tun_meta.peer.dbid,) + path
                        rvpeer = far_peers_by_path.get(apath)
                        if rvpeer is None:
                            #FIXME: Treat this as attack, Etc.
                            log.warning("Far node not found in dict for apath"\
                                "[{}].".format(apath))
                        else:
                            rvpeer.will_store = True
                            data_rw.will_store_cnt += 1
                    else:
                        if len(pkts) == 1:
                            # If a node has no closer peers, it may close
                            # the channel after sending the StorageInterest
                            # message instead of also sending a PeerList.
                            tun_meta.jobs -= 1
                            query_cntr.value -= 1
                            if not query_cntr.value:
                                done_one.set()
                                done_all.set()
                            elif len(path) == depth.value:
                                done_one.set()
                            continue

                pkt = pkts[1]
            else:
                pkt = pkts[0]

            pmsg = cp.ChordPeerList(pkt)

            if log.isEnabledFor(logging.INFO):
                log.info("Peer (tun_meta.peer.dbid=[{}], path=[{}]) returned"\
                    " PeerList of size {}."\
                    .format(tun_meta.peer.dbid, path, len(pmsg.peers)))

            # Add returned PeerS to result_trie.
            idx = 0
            for rpeer in pmsg.peers:
                end_path = path + (idx,)

                vpeer = VPeer(rpeer, end_path, tun_meta)

                key = bittrie.XorKey(node_id, rpeer.node_id)
                result_trie.setdefault(key, vpeer)

                if data_mode.value:
                    apath = (tun_meta.peer.dbid,) + end_path
                    far_peers_by_path.setdefault(apath, vpeer)

                idx += 1

            if not tun_meta.jobs:
                #FIXME: Should handle this as an attack and ignore them and
                # update tracking of hostility of the Peer AND tunnel.
                log.info(\
                    "Got extra result from tunnel (Peer.id={}, path=[{}])."\
                        .format(tun_meta.peer.dbid, path))
                continue

            tun_meta.jobs -= 1
            query_cntr.value -= 1
            if not query_cntr.value:
                done_one.set()
                done_all.set()

        return True

    def unwrap_relay_packets(self, pkt, data_mode):
        "Returns the inner most packet and the path stored in the relay"\
        " packets."

        path = []
        invalid = False

        while True:
            msg = cp.ChordRelay(pkt)
            path.append(msg.index)
            pkts = msg.packets

            if len(pkts) == 1:
                pkt = pkts[0]

                packet_type = cp.ChordMessage.parse_type(pkt)
                if packet_type == cp.CHORD_MSG_RELAY:
                    continue
                elif packet_type == cp.CHORD_MSG_PEER_LIST\
                        or (data_mode is cp.DataMode.get\
                            and (packet_type == cp.CHORD_MSG_DATA_RESPONSE\
                                or packet_type == cp.CHORD_MSG_DATA_PRESENCE))\
                        or (data_mode is cp.DataMode.store\
                            and (packet_type == cp.CHORD_MSG_DATA_STORED\
                                or packet_type\
                                    == cp.CHORD_MSG_STORAGE_INTEREST)):
                    # Break as we reached deepest packet.
                    break
                else:
                    log.warning("Unexpected packet_type [{}]; ignoring."\
                        .format(packet_type))
                    invalid = True
                    break
            elif len(pkts) > 1:
                # In data mode, PeerS return their storage intent, as well as a
                # list of their connected PeerS.
                if data_mode.value:
                    if data_mode is cp.DataMode.get\
                            and (cp.ChordMessage.parse_type(pkts[0])\
                                    != cp.CHORD_MSG_DATA_PRESENCE\
                                or cp.ChordMessage.parse_type(pkts[1])\
                                    != cp.CHORD_MSG_PEER_LIST):
                        invalid = True
                    elif data_mode is cp.DataMode.store\
                            and (cp.ChordMessage.parse_type(pkts[0])\
                                    != cp.CHORD_MSG_STORAGE_INTEREST\
                                or cp.ChordMessage.parse_type(pkts[1])\
                                    != cp.CHORD_MSG_PEER_LIST):
                        invalid = True
                else:
                    invalid = True

                # Break as we reached deepest packets.
                break
            else:
                # There should never be an empty relay packet embedded when
                # this method is called.
                invalid = True
                break

        if invalid:
            #FIXME: We should probably update the hostility tracking of both
            # the Peer and the tunnel Peer instead of just ignoring this
            # invalid state.
            log.warning("Unwrapping found invalid state.")

            pkts = []

            if data_mode is cp.DataMode.get:
                pkts.append(cp.ChordDataPresence().encode())
            elif data_mode is cp.DataMode.store:
                pkts.append(cp.ChordStorageInterest().encode())

            tpeerlist = cp.ChordPeerList()
            tpeerlist.peers = []
            pkts.append(tpeerlist.encode())

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Unwrapped {} packets.".format(len(pkts)))

        return pkts, path

    @asyncio.coroutine
    def _wait_for_data_stored(self, data_mode, vpeer, tun_meta, sreq,\
            query_cntr, done_one, done_all, data_rw):
        "This is a coroutine that is used in data_mode and is started for"\
        " immediate PeerS that do not have a tunnel open (and thus a tunnel"\
        " coroutine already processing it."

        while True:
            pkt = yield from tun_meta.queue.get()
            if not pkt:
                break

            packet_type = cp.ChordMessage.parse_type(pkt)

            if packet_type != cp.CHORD_MSG_DATA_STORED\
                    and packet_type != cp.CHORD_MSG_DATA_RESPONSE:
                # Ignore late packets from stage 1.
                continue

            if data_mode is cp.DataMode.get:
                try:
                    rmsg = cp.ChordDataResponse(pkt)

                    r = yield from self._process_data_response(\
                        sreq, rmsg, tun_meta, None, data_rw)
                except Exception:
                    r = None
                    if log.isEnabledFor(logging.INFO):
                        log.info(\
                            "Peer [{}] sent corrupt ChordDataResponse."\
                                .format(vpeer))

                if not r:
                    # If the data was invalid, we will try from another
                    # Peer (or possibly tunnel).
                    log.info("Data in response did not match request"\
                        " key.")
                    tun_meta.jobs -= 1
                    query_cntr.value -= 1
                    assert not query_cntr.value
                    done_all.set()
                    continue
            else:
                assert data_mode is cp.DataMode.store

                msg = cp.ChordDataStored(pkt)

                if msg.stored:
                    data_rw.storing_nodes += 1

            break

        if tun_meta.jobs:
            assert tun_meta.jobs == 1
            tun_meta.jobs -= 1
            query_cntr.value -= 1
            done_one.set()
            if not query_cntr.value:
                done_all.set()

    ###########################################################################
    # Start of incoming request processing.

    @asyncio.coroutine
    def process_find_node_request(self, fnmsg, fndata, peer, queue, local_cid):
        "Process an incoming FindNode request."\
        " The channel will be closed before this method returns."

        pt = bittrie.BitTrie()

        for cpeer in self.engine.peers.values():
            if cpeer == peer:
                # Don't include asking peer.
                continue
            if not cpeer.full_node:
                continue
            if not cpeer.ready:
                continue

            pt[bittrie.XorKey(fnmsg.node_id, cpeer.node_id)] = cpeer

#        # We don't want to deal with further nodes than ourselves.
#        pt[bittrie.XorKey(fnmsg.node_id, self.engine.node_id)] = True

        cnt = 20
        rlist = []

        for r in pt:
#            if r is True:
#                log.info("No more nodes closer than ourselves.")
#                break

            if log.isEnabledFor(logging.DEBUG):
                log.debug("nn: {} FOUND: {:7} {:22} node_id=[{}] diff=[{}]"\
                    .format(self.engine.node.instance, r.dbid, r.address,\
                        mbase32.encode(r.node_id),\
                        mutil.hex_string(\
                            mutil.calc_raw_distance(\
                                r.node_id, fnmsg.node_id))))

            rlist.append(r)

            cnt -= 1
            if not cnt:
                break

        # Free memory? We no longer need this, and we may be tunneling for
        # some time.
        pt = None

        will_store = False
        need_pruning = False
        data_present = False
        if fnmsg.data_mode.value:
            # In for_data mode we respond with two packets.
            if fnmsg.data_mode is cp.DataMode.get:
                data_present = yield from self._check_has_data(\
                    fnmsg.node_id, fnmsg.significant_bits, fnmsg.target_key,\
                    fnmsg.query)

                pmsg = cp.ChordDataPresence()
                if fnmsg.significant_bits and data_present:
                    pmsg.first_id = data_present
                else:
                    pmsg.data_present = data_present

                if log.isEnabledFor(logging.INFO):
                    data_present_val =\
                        data_present if type(data_present) is bool\
                            else mbase32.encode(data_present)

                    log.info(\
                        "Writing DataPresence (data_id=[{}], data_present="\
                            "[{}]) response."\
                                .format(\
                                    mbase32.encode(fnmsg.node_id),\
                                    data_present_val))

                peer.protocol.write_channel_data(local_cid, pmsg.encode())
            elif fnmsg.data_mode is cp.DataMode.store:
                will_store, need_pruning =\
                    yield from self._check_do_want_data(\
                        fnmsg.node_id, fnmsg.version)

                imsg = cp.ChordStorageInterest()
                imsg.will_store = will_store

                if log.isEnabledFor(logging.INFO):
                    log.info(\
                        "Writing StorageInterest (data_id=[{}], will_store="\
                            "[{}]) response."\
                                .format(\
                                    mbase32.encode(fnmsg.node_id),\
                                    will_store))

                peer.protocol.write_channel_data(local_cid, imsg.encode())
            else:
                log.warning("Invalid data_mode ([{}])."\
                    .format(fnmsg.data_mode))

        if not rlist:
            log.info("No nodes closer than ourselves.")
            if not will_store and (fnmsg.significant_bits or not data_present):
                yield from peer.protocol.close_channel(local_cid)
                return

        lmsg = cp.ChordPeerList()
        lmsg.peers = rlist

        log.info("Writing PeerList (size={}) response.".format(len(rlist)))
        peer.protocol.write_channel_data(local_cid, lmsg.encode())

        rlist = [TunnelMeta(rpeer) for rpeer in rlist]

        tun_cntr = Counter(len(rlist))

        while True:
            pkt = yield from queue.get()
            if not pkt:
                # If the requestor channel closes, or the connection went down,
                # then abort the FindNode completely.
                yield from self._close_tunnels(rlist)
                return

            if not tun_cntr.value and not will_store and not data_present:
                # If all the tunnels were closed and we aren't waiting for
                # data, then we clean up and exit.
                yield from self._close_tunnels(rlist)
                yield from peer.protocol.close_channel(local_cid)
                return

            packet_type = cp.ChordMessage.parse_type(pkt)
            if will_store:
                if packet_type == cp.CHORD_MSG_STORE_DATA:
                    if log.isEnabledFor(logging.INFO):
                        log.info("Received ChordStoreData packet, storing.")

                    rmsg = cp.ChordStoreData(pkt)

                    if rmsg.targeted and rmsg.data[:16] != MorphisBlock.UUID:
                        r = yield from self._store_synapse(\
                            peer, fnmsg.node_id, rmsg, need_pruning)
                    else:
                        r = yield from self._store_data(\
                            peer, fnmsg.node_id, rmsg, need_pruning)

                    dsmsg = cp.ChordDataStored()
                    dsmsg.stored = r

                    peer.protocol.write_channel_data(local_cid, dsmsg.encode())
                    continue
                elif packet_type == cp.CHORD_MSG_STORE_KEY:
                    if log.isEnabledFor(logging.INFO):
                        log.info("Received ChordStoreKey packet, storing.")

                    rmsg = cp.ChordStoreKey(pkt)

                    r = yield from self._store_key(peer, fnmsg.node_id, rmsg)

                    dsmsg = cp.ChordDataStored()
                    dsmsg.stored = r

                    peer.protocol.write_channel_data(local_cid, dsmsg.encode())
                    continue
                else:
                    rmsg = cp.ChordRelay(pkt)
            elif data_present and packet_type == cp.CHORD_MSG_GET_DATA:
                if log.isEnabledFor(logging.INFO):
                    log.info("Received ChordGetData packet, fetching.")

                if fnmsg.significant_bits:
                    # data_present was set to the closest that we have.
                    data_id = data_present
                else:
                    data_id = fnmsg.node_id

                data, data_l, version, signature, epubkey, pubkeylen =\
                    yield from self._retrieve_data(data_id, fnmsg.query)

#                assert data is not None

                drmsg = cp.ChordDataResponse()
                if data is not None:
                    drmsg.data = data
                    drmsg.original_size = data_l
                    if version is not None:
                        drmsg.version = version
                        drmsg.signature = signature
                        if epubkey:
                            drmsg.epubkey = epubkey
                            drmsg.pubkeylen = pubkeylen
                else:
                    drmsg.data = b""
                    drmsg.original_size = 0

                peer.protocol.write_channel_data(local_cid, drmsg.encode())

                # After we return the data, since we are honest, there is no
                # point in the requesting node asking for data from one of our
                # immediate PeerS through us as a tunnel, so we clean up and
                # exit.
                yield from self._close_tunnels(rlist)
                yield from peer.protocol.close_channel(local_cid)
                return
            else:
                rmsg = cp.ChordRelay(pkt)

            if log.isEnabledFor(logging.DEBUG):
                log.debug("Processing request from Peer (id=[{}]) for index"\
                    " [{}].".format(peer.dbid, rmsg.index))

            tun_meta = rlist[rmsg.index]

            if not tun_meta.queue:
                # First packet to a yet to be utilized Peer should be empty,
                # which instructs us to open the tunnel and forward it the root
                # FindNode packet that started this process.
                if len(rmsg.packets):
                    log.warning("Peer sent invalid packet (not empty but"\
                        " tunnel not yet opened) for index [{}]; skipping."\
                        .format(rmsg.index))
                    continue

                tun_meta.jobs = asyncio.Queue()
                asyncio.async(\
                    self._process_find_node_tunnel(\
                        peer, local_cid, rmsg.index, tun_meta, tun_cntr,\
                        fnmsg.data_mode),\
                    loop=self.loop)
                yield from tun_meta.jobs.put(fndata)
            elif tun_meta.jobs:
                if not len(rmsg.packets):
                    log.warning("Peer [{}] sent additional empty relay packet"\
                        " for tunnel [{}]; skipping."\
                            .format(peer.dbid, rmsg.index))
                    continue
                if len(rmsg.packets) > 1:
                    log.warning("Peer [{}] sent relay packet with more than"\
                        " one embedded packet for tunnel [{}]; skipping."\
                            .format(peer.dbid, rmsg.index))
                    continue

                e_pkt = rmsg.packets[0]

                if cp.ChordMessage.parse_type(e_pkt) != cp.CHORD_MSG_RELAY:
                    if not fnmsg.data_mode.value:
                        log.warning("Peer [{}] sent a non-empty relay packet"\
                            " with other than a relay packet embedded for"\
                            " tunnel [{}]; skipping."\
                                .format(peer.dbid, rmsg.index))
                        continue
                    # else: It is likely a {Get,Store}Data message, which is
                    # ok.

                # If all good, tell tunnel process to forward embedded packet.
                yield from tun_meta.jobs.put(e_pkt)
            else:
                if log.isEnabledFor(logging.INFO):
                    log.info("Skipping request for disconnected tunnel [{}]."\
                        .format(rmsg.index))

                yield from self._signal_find_node_tunnel_closed(\
                    peer, local_cid, rmsg.index, 1)

    @asyncio.coroutine
    def _process_find_node_tunnel(\
            self, rpeer, rlocal_cid, index, tun_meta, tun_cntr, data_mode):
        assert type(rpeer) is mnpeer.Peer

        "Start a tunnel to the Peer in tun_meta by opening a channel and then"
        " passing all packets put into the tun_meta.jobs queue to the Peer."
        " Another coroutine is started to process the responses and send them"
        " back to the Peer passed in rpeer."

        if log.isEnabledFor(logging.INFO):
            log.info("Opening tunnel [{}] to Peer (id=[{}]) for Peer(id=[{}])."\
                .format(index, tun_meta.peer.dbid, rpeer.dbid))

        tun_meta.local_cid, tun_meta.queue =\
            yield from tun_meta.peer.protocol.open_channel("mpeer", True)
        if not tun_meta.queue:
            tun_cntr.value -= 1

            job_cnt = tun_meta.jobs.qsize()
            tun_meta.jobs = None
            assert job_cnt == 1

            yield from\
                self._signal_find_node_tunnel_closed(\
                    rpeer, rlocal_cid, index, job_cnt)
            return

        req_cntr = Counter(0)

        asyncio.async(\
            self._process_find_node_tunnel_responses(\
                rpeer, rlocal_cid, index, tun_meta, req_cntr, data_mode),
            loop=self.loop)

        jobs = tun_meta.jobs
        while True:
            pkt = yield from jobs.get()
            if not pkt or not tun_meta.jobs:
                tun_cntr.value -= 1
                yield from\
                    tun_meta.peer.protocol.close_channel(tun_meta.local_cid)
                return

            if log.isEnabledFor(logging.DEBUG):
                log.debug("Relaying request (index={}) from Peer (id=[{}])"\
                    " to Peer (id=[{}])."\
                    .format(index, rpeer.dbid, tun_meta.peer.dbid))

            tun_meta.peer.protocol.write_channel_data(tun_meta.local_cid, pkt)

            req_cntr.value += 1

    @asyncio.coroutine
    def _process_find_node_tunnel_responses(\
            self, rpeer, rlocal_cid, index, tun_meta, req_cntr, data_mode):
        "Process the responses from a tunnel and relay them back to rpeer."

        tunnel_closed = False

        while True:
            pkt = yield from tun_meta.queue.get()
            if not tun_meta.jobs:
                return
            if not pkt:
                break

            pkt2 = None
            if data_mode.value:
                pkt_type = cp.ChordMessage.parse_type(pkt)

                # These exceptions are for packets directly from the immediate
                # Peer, as opposed to relay packets containing responses from
                # PeerS being accessed through the immediate Peer acting as a
                # tunnel.

                if data_mode is cp.DataMode.get\
                        and pkt_type == cp.CHORD_MSG_DATA_RESPONSE:
                    #TODO: Verify the data matches the key before relaying.
                    # Relay the DataResponse from immediate Peer.
                    pass
                elif data_mode is cp.DataMode.store\
                        and pkt_type == cp.CHORD_MSG_DATA_STORED:
                    # Relay the DataStored from immediate Peer.
                    pass
                elif pkt_type != cp.CHORD_MSG_RELAY:
                    # First two packets from a newly opened tunnel in data_mode
                    # mode will be the DataPresence or StorageInterest\
                    # and PeerList packet.
                    pkt2 = yield from tun_meta.queue.get()
                    if not tun_meta.jobs:
                        return
                    if not pkt2:
                        # FindNode for key can send just one packet and then
                        # close the tunnel if it had no closer nodes.
                        if pkt_type != cp.CHORD_MSG_DATA_PRESENCE\
                                and pkt_type != cp.CHORD_MSG_STORAGE_INTEREST:
                            log.warning("Tunnel closed before expected second"\
                                " packet; first pkt_type=[{}]."\
                                    .format(pkt_type))
                            break
                        tunnel_closed = True

            if log.isEnabledFor(logging.DEBUG):
                log.debug("Relaying response (index={}) from Peer (id=[{}])"\
                    " to Peer (id=[{}])."\
                    .format(index, tun_meta.peer.dbid, rpeer.dbid))

            msg = cp.ChordRelay()
            msg.index = index
            if pkt2:
                msg.packets = [pkt, pkt2]
            else:
                msg.packets = [pkt]

            rpeer.protocol.write_channel_data(rlocal_cid, msg.encode())

            req_cntr.value -= 1

            if tunnel_closed:
                break

        outstanding = tun_meta.jobs.qsize() + req_cntr.value
        yield from\
            self._signal_find_node_tunnel_closed(\
                rpeer, rlocal_cid, index, outstanding)

        jobs = tun_meta.jobs
        tun_meta.jobs = None
        yield from jobs.put(None)

    @asyncio.coroutine
    def _signal_find_node_tunnel_closed(self, rpeer, rlocal_cid, index, cnt):
        rmsg = cp.ChordRelay()
        rmsg.index = index
        rmsg.packets = [EMPTY_PEER_LIST_PACKET]
        pkt = rmsg.encode()

        for _ in range(cnt):
            # Signal the query finished with no results.
            rpeer.protocol.write_channel_data(rlocal_cid, pkt)

    @asyncio.coroutine
    def _close_tunnels(self, meta_list):
        for tun_meta in meta_list:
            if not tun_meta.queue:
                continue
            if tun_meta.jobs:
                jobs = tun_meta.jobs
                tun_meta.jobs = None
                yield from jobs.put(None)

            yield from\
                tun_meta.peer.protocol.close_channel(tun_meta.local_cid)

    @asyncio.coroutine
    def _check_has_data(self, data_id, significant_bits, target_key, sreq):
        if sreq:
            return (yield from self._check_synapse_request(sreq))

        if log.isEnabledFor(logging.INFO):
            target_key_enc =\
                mbase32.encode(target_key) if target_key is not None else None
            log.info("Checking for data_id=[{}], significant_bits=[{}],"\
                " target_key=[{}]."\
                    .format(mbase32.encode(data_id), significant_bits,\
                        target_key_enc))

        distance = mutil.calc_raw_distance(self.engine.node_id, data_id)

        if significant_bits:
            mask = ((1 << (chord.NODE_ID_BITS - significant_bits)) - 1)\
                .to_bytes(chord.NODE_ID_BYTES, "big")

            end_id = bytearray()

            for c1, c2 in zip(data_id, mask):
                end_id.append(c1 | c2)

            if distance > self.engine.furthest_data_block:
                d2 = mutil.calc_raw_distance(self.engine.node_id, end_id)
                if d2 > self.engine.furthest_data_block:
                    return False
        else:
            if distance > self.engine.furthest_data_block:
                return False

        def dbcall():
            with self.engine.node.db.open_session() as sess:
                if significant_bits:
                    # Wildcard key search mode.
                    q = sess.query(DataBlock.data_id)

                    q = q.filter(DataBlock.data_id > data_id)
                    q = q.filter(DataBlock.data_id <= end_id)

                    if target_key:
                        # This is the feature that makes it so spammers are
                        # forced to target each destination individually with
                        # while generating a the proof of work.
                        q = q.filter(DataBlock.target_key == target_key)

                    q = q.filter(DataBlock.original_size == 0)
                    q = q.order_by(DataBlock.data_id)

                    next_block_id = q.first()

                    if next_block_id:
                        return next_block_id[0]
                    else:
                        return False
                else:
                    q1 = sess.query(DataBlock.data_id)
                    q2 = sess.query(SynapseKey.data_id)\
                        .filter(\
                            or_(\
                                SynapseKey.key_type\
                                    == SynapseKey.KeyType.synapse_pow.value,
                                SynapseKey.key_type\
                                    == SynapseKey.KeyType.synapse_key.value))

                    q3 = q1.union(q2).filter_by(data_id = data_id)

                    q = sess.query(func.count("*")).select_from(q3.subquery())

                    if q.scalar() > 0:
                        return True
                    else:
                        return False

        return (yield from self.loop.run_in_executor(None, dbcall))

    @asyncio.coroutine
    def _check_synapse_request(self, sreq):
        def dbcall():
            with self.engine.node.db.open_session() as sess:
                q = sess.query(SynapseKey.data_id)

                q = self._build_synapse_db_query(sess, q, sreq)

                q = sess.query(func.count("*")).select_from(q.subquery())

                if q.scalar() > 0:
                    return True
                else:
                    return False

        return (yield from self.loop.run_in_executor(None, dbcall))

    def _build_synapse_db_query(self, sess, q, sreq):
        if sreq.start_timestamp:
            q = q.filter(SynapseKey.timestamp >= sreq.start_timestamp)
        if sreq.end_timestamp:
            q = q.filter(SynapseKey.timestamp < sreq.end_timestamp)
        if sreq.minimum_pow:
            q = q.filter(SynapseKey.pow_difficulty >= sreq.minimum_pow)

        synapse_query = sreq.query

        type_ = synapse_query.type

        if type_ is syn.SynapseRequest.Query.Type.and_\
                or type_ is syn.SynapseRequest.Query.Type.or_:
            assert len(synapse_query.entries) == 2

            #TODO: YOU_ARE_HERE
            raise ChordException("TODO.")
        elif type_ is syn.SynapseRequest.Query.Type.key:
            kq = synapse_query.entries
            assert len(kq.value) == 64
            q = q.filter(SynapseKey.key_type == kq.type.value + 2)\
                .filter(SynapseKey.data_id == kq.value)
        else:
            log.warning("Ignoring unsupported SynapseRequest.Query.Type [{}]."\
                .format(type_))

        # Since paging + save coding time, we always sort.
        als = aliased(SynapseKey)

        q = q.join(als, SynapseKey.synapse_id == als.synapse_id)
        q = q.filter(\
            als.key_type == SynapseKey.KeyType.synapse_key.value)

        if sreq.start_key:
            q = q.filter(als.data_id >= sreq.start_key)
        if sreq.end_key:
            q = q.filter(als.data_id <= sreq.end_key)

        q = q.order_by(als.data_id)

        return q

    @asyncio.coroutine
    def _check_do_want_data(self, data_ids, version):
        "Checks if we have space to store, and if not if we have enough data"\
        " that is further in distance thus having enough space to free."\
        "returns: will_store, need_pruning"

        # If there are multiple IDs passed in, then for now we will just check
        # the closest ID to our node_id.
        if type(data_ids) is list:
            if len(data_ids) == 2:
                back = data_ids[0]
                foward = data_ids[1]
            else:
                input_trie = bittrie.BitTrie()
                for key in data_ids:
                    input_trie[key] = True
                back = input_trie.find(self.engine.node_id, forward=False)
                forward = input_trie.find(self.engine.node_id, forward=True)

            fdist = mutil.calc_raw_distance(self.engine.node_id, forward)
            bdist = mutil.calc_raw_distance(self.engine.node_id, back)

            if fdist <= bdist:
                data_id = forward
            else:
                data_id = back
        else:
            data_id = data_ids

        if self.engine.node.datastore_size\
                < self.engine.node.datastore_max_size:
#            # We only store stuff closer than 2^2 less then the maximum
#            # distance.
#            log_dist, direction =\
#                mutil.calc_log_distance(self.engine.node_id, data_id)
#            if log_dist > chord.NODE_ID_BITS - 2:
#                # Too far.
#                if log.isEnabledFor(logging.DEBUG):
#                    log.debug("Don't want data; too far.")
#                return False, False

            # Check if we have this block.
            def dbcall():
                with self.engine.node.db.open_session() as sess:
                    if version:
                        old_entry = sess.query(DataBlock)\
                            .filter(DataBlock.data_id == data_id)\
                            .first()

                        if old_entry:
                            vint = int(old_entry.version)
                            if vint >= version:
                                # We only want to store newer versions.
                                return False
                    else:
                        q = sess.query(func.count("*")).select_from(DataBlock)
                        q = q.filter(DataBlock.data_id == data_id)

                        if q.scalar() > 0:
                            # We already have this block.
                            return False

                    return True

            r = yield from self.loop.run_in_executor(None, dbcall)

            if not r:
                if log.isEnabledFor(logging.DEBUG):
                    log.debug("Don't want data; already have it.")

            return r, False

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Datastore is full, checking if proposed block is"\
                " closer than enough stored blocks to fit with a purge.")
        elif log2.isEnabledFor(logging.INFO):
            log2.info("Datastore is full, checking if proposed block is"\
                " closer than enough stored blocks to fit with a purge.")

        distance = mutil.calc_raw_distance(self.engine.node_id, data_id)

        if distance > self.engine.furthest_data_block:
            return False, False

        current_datastore_size = self.engine.node.datastore_size
        current_datastore_max_size = self.engine.node.datastore_max_size

        # If there is space contention, then we do a more complex algorithm
        # in order to see if we want to store it.
        def dbcall():
            with self.engine.node.db.open_session() as sess:
                # First check if we have this block already.
                q = sess.query(func.count("*")).select_from(DataBlock)
                q = q.filter(DataBlock.data_id == data_id)

                if q.scalar() > 0:
                    # We already have this block.
                    return False

                # We don't worry about inaccuracy caused by padding for now.
                q = sess.query(DataBlock.original_size)\
                    .filter(DataBlock.distance > distance)\
                    .filter(DataBlock.original_size != 0)\
                    .order_by(DataBlock.distance.desc())

                freeable_space = 0
                for block in mutil.page_query(q):
                    freeable_space += block.original_size

                    if current_datastore_size - freeable_space\
                            <= current_datastore_max_size\
                                - mnnode.MAX_DATA_BLOCK_SIZE:
                        if log.isEnabledFor(logging.DEBUG):
                            log.debug("Found enough purgable blocks to fit"\
                                " new proposed block.")
                        return True

                assert current_datastore_size - freeable_space\
                    > current_datastore_max_size - mnnode.MAX_DATA_BLOCK_SIZE

                if log.isEnabledFor(logging.DEBUG):
                    log.debug("Not enough purgable blocks to fit new"\
                        " proposed block.")
                return False

        return (yield from self.loop.run_in_executor(None, dbcall)), True

    @asyncio.coroutine
    def _process_own_data(self, data_id, data_rw, sreq):
        enc_data, data_l, version, signature, epubkey,\
            pubkeylen =\
                yield from self._retrieve_data(data_id, sreq)

        if enc_data is None:
            return False

        log.info("We had the data; fetching.")

        drmsg = cp.ChordDataResponse()
        drmsg.data = enc_data
        drmsg.original_size = data_l
        if version is not None:
            drmsg.version = version
            drmsg.signature = signature
            if epubkey:
                drmsg.epubkey = epubkey
                drmsg.pubkeylen = pubkeylen

        r = yield from\
            self._process_data_response(sreq, drmsg, None, None, data_rw)

        return r

    @asyncio.coroutine
    def _process_data_response(self, sreq, drmsg, tun_meta, path, data_rw):
        "Processes the DataResponse message, storing the decrypted data into"\
        " data_rw if it matches the original key. Returns True on success,"\
        " False otherwise."

        if log.isEnabledFor(logging.INFO):
            peer_dbid = tun_meta.peer.dbid if tun_meta else "<self>"
            log.info("Received DataResponse (version=[{}]) from Peer [{}]"\
                " and path [{}] (targeted=[{}])."\
                    .format(drmsg.version, peer_dbid, path, data_rw.targeted))

        def threadcall():
            if data_rw.targeted or drmsg.version == -1:
                # TargetedBlock/Synapse mode.
                if drmsg.version is None:
                    # TargetedBlock mode.
                    data = self._decrypt_data_response(drmsg, data_rw.data_key)

                    valid, data_key =\
                        self._check_targeted_block(data, data_rw.data_key)
                else:
                    assert drmsg.version == -1
                    # Synapse mode.
                    data = self._decrypt_data_response(drmsg, data_rw.data_key)

                    # SynapseS are encrypted with random key of storing PeerS
                    # creation. The storing Peer then stores the random key
                    # encrypted with the request key. The storing node then
                    # returns that encrypted random key to us in the data
                    # response. We just decrypt the random key with the request
                    # key and then use that result to decrypt the data!
                    # The above is all due to anti-entrapment functionality.

                    # We repurposed the signature field to store the encrypted
                    # random key, and the version field of -1 signified such.
                    # This was to maintain backwards net compatability for now.

                    data_key = enc.decrypt_data_block(\
                        drmsg.signature, data_rw.data_key)

                    data = self._decrypt_data_response(drmsg, data_key)

                    valid = self._check_synapse(data, data_rw.data_key)

                if not valid:
                    if log.isEnabledFor(logging.INFO):
                        log.info("DataResponse is invalid!")
                    return None
                else:
                    # valid holds a TargetedBlock or Synapse.
                    data_rw.object = valid

                if data_rw.target_key is not None and\
                        data_rw.target_key != valid.target_key:
                    if log.isEnabledFor(logging.INFO):
                        log.info("Unexpected target_key in header;"\
                            " DataResponse is invalid!")
                    return None

                # Everything checks out for targeted.
            elif drmsg.version is not None:
                # Updateable key mode.
                data = self._decrypt_data_response(drmsg, data_rw.data_key)

                data_hash = enc.generate_ID(data)

                data_rw.version = drmsg.version

                if data_rw.pubkey:
                    pubkey = data_rw.pubkey
                else:
                    pubkey = enc.decrypt_data_block(\
                        drmsg.epubkey, data_rw.data_key)
                    # Truncate the key data to exclude the cipher padding.
                    pubkey = pubkey[:drmsg.pubkeylen]

                    # Return the pubkey to the original caller.
                    data_rw.pubkey = pubkey

                    data_key = enc.generate_ID(pubkey)
                    if data_rw.path_hash:
                        data_key =\
                            enc.generate_ID(data_key + data_rw.path_hash)

                    if data_key != data_rw.data_key:
                        if log.isEnabledFor(logging.INFO):
                            log.info("DataResponse is invalid!")
                        return None

                # Return the signature to the original caller.
                data_rw.signature = drmsg.signature

                hm = bytearray()
                hm += sshtype.encodeBinary(data_rw.path_hash)
                hm += sshtype.encodeMpint(drmsg.version)
                hm += sshtype.encodeBinary(data_hash)

                valid =\
                    rsakey.RsaKey(pubkey).verify_ssh_sig(hm, drmsg.signature)
            else:
                # Static key mode.
                data = self._decrypt_data_response(drmsg, data_rw.data_key)

                # Verify that the decrypted data matches the original hash we
                # requested.
                data_hash = enc.generate_ID(data)
                valid = data_hash == data_rw.data_key

            if not valid:
                if log.isEnabledFor(logging.INFO):
                    log.info("DataResponse is invalid!")
                return None

            if log.isEnabledFor(logging.DEBUG):
                log.debug("DataResponse is valid.")

            return data

        if sreq:
            if not type(drmsg.data) is list:
                log.info(\
                    "ChordDataResponse contained other than list for"\
                    " SynapseRequest.")
                return False
            r = self._process_synapse_data_response(drmsg, data_rw)
        elif len(drmsg.data) == 0:
            # This can happen if a node had an error, it sends an empty one so
            # we aren't waiting.
            log.info("DataReponse is empty.")
            return False
        else:
            # Normal non-Synapse response handling.
            r = yield from self.loop.run_in_executor(None, threadcall)

        if r is not None:
            data_rw.data = r
            data_rw.data_done.set()
            return True
        else:
            data_rw.data_done.set()
            return False

    def _process_synapse_data_response(self, drmsg, data_rw):
        synapses = []

        if log.isEnabledFor(logging.INFO):
            log.info("Processing SyanpseRequest response.")

        for eekey, edata, osize in drmsg.data:
            ekey = enc.decrypt_data_block(eekey, data_rw.data_key)
            data = enc.decrypt_data_block(edata, ekey)

            synapse = self._check_synapse(data)

            if synapse:
                synapses.append(synapse)

        if log.isEnabledFor(logging.INFO):
            log.info(\
                "Response contained [{}] valid Synapses."\
                    .format(len(synapses)))

        data_rw.object = synapses
        data_rw.limited = drmsg.limited

        return synapses

    def _decrypt_data_response(self, drmsg, data_key):
        # Decrypt the data we received.
        data = enc.decrypt_data_block(drmsg.data, data_key)

        # Truncate the data to exclude the cipher padding.
        data = data[:drmsg.original_size]

#TODO: Debug stuff, delete.
#            log.warning(\
#                "before=[\n{}], after=[\n{}]."\
#                    .format(mutil.hex_dump(data), mutil.hex_dump(drmsg.data)))

        return data

    @asyncio.coroutine
    def _retrieve_data(self, data_id, synapse_request):
        "Retrieve data for data_id from the file system (and meta data from"\
        " the database."\
        "returns: data, original_size,\
                <version, signature, epubkey, pubkeylen>"\
        "   original_size is the size of the data before it was encrypted."\
        "   version, Etc. are for updateable keys."

        if synapse_request:
            return (yield from self._synapse_request(synapse_request))

        def dbcall():
            with self.engine.node.db.open_session() as sess:
                data_block = sess.query(DataBlock).filter(\
                    DataBlock.data_id == data_id).first()

                if data_block:
                    sess.expunge(data_block)
                    return data_block

                # Otherwise, check the SynapseKey table for a matching Synapse.
                synapse = sess.query(Synapse).options(joinedload("keys"))\
                    .join(Synapse.keys).filter(\
                        or_(\
                            SynapseKey.key_type\
                                == SynapseKey.KeyType.synapse_pow.value,
                            SynapseKey.key_type\
                                == SynapseKey.KeyType.synapse_key.value))\
                        .filter(SynapseKey.data_id == data_id).first()

                if synapse:
                    sess.expunge(synapse)
                    return synapse

                return None

        result = yield from self.loop.run_in_executor(None, dbcall)

        if not result:
            if log.isEnabledFor(logging.DEBUG):
                log.debug(\
                    "Requested data was not found in the database!"\
                    " (data_id=[{}]."\
                        .format(mbase32.encode(data_id)))
            return None, None, None, None, None, None

        if type(result) is Synapse:
            for key in result.keys:
                if key.data_id == data_id:
                    found = True
                    break

            assert found

            return result.data, result.original_size, -1, key.ekey, None, None

        assert type(result) is DataBlock, type(result)

        if log.isEnabledFor(logging.INFO):
            log.info("Loading data id=[{}] to respond to data request."\
                .format(mbase32.encode(data_id)))
        elif log2.isEnabledFor(logging.INFO):
            log2.info("Loading data id=[{}] to respond to data request."\
                .format(mbase32.encode(data_id)))

        def iocall():
            filename = self.engine.node.data_block_file_path.format(\
                self.engine.node.instance, result.id)

            try:
                with open(filename, "rb") as data_file:
                    data = data_file.read()
                    return data
            except FileNotFoundError:
                return None

        enc_data = yield from self.loop.run_in_executor(None, iocall)

        if enc_data is None:
            log.warning("Block id=[{}] was missing; Removing DB entry."\
                .format(result.id))

            def dbcall_prune():
                with self.engine.node.db.open_session() as sess:
                    sess.query(DataBlock)\
                        .filter(DataBlock.id == result.id)\
                            .delete(synchronize_session=False)
                    sess.commit()

            yield from self.loop.run_in_executor(None, dbcall_prune)

            return None, None, None, None, None, None

        # This next line is because we use a String in the database as SQLite
        # does not support any bigint.
        version =\
            int(result.version) if result.version is not None else None

        return enc_data, result.original_size, version,\
            result.signature, result.epubkey, result.pubkeylen

    @asyncio.coroutine
    def _synapse_request(self, synapse_request):
        def dbcall():
            with self.engine.node.db.open_session() as sess:
                q = sess.query(Synapse, SynapseKey)\
                    .join(Synapse.keys)

                q = self._build_synapse_db_query(sess, q, synapse_request)

                # No more than 256 SynapseS should be able to fit in one 32k
                # packet.
                return q.limit(256).all()

        result = yield from self.loop.run_in_executor(None, dbcall)

        log.warning("Found [{}] results.".format(len(result)))

        synapses = []

        for synapse, key in result:
            synapses.append((key.ekey, synapse.data, synapse.original_size))

        return synapses, None, None, None, None, None

    @asyncio.coroutine
    def _store_key(self, peer, data_id, dmsg):
        if dmsg.targeted:
            valid = False
            if dmsg.data[:16] == MorphisBlock.UUID:
                valid, data_key =\
                    self._check_targeted_block(dmsg.data, data_id)
            else:
                valid = self._check_synapse(dmsg.data, data_id)
        else:
            data_key = enc.generate_ID(dmsg.data)
            valid = data_id == data_key

        if not valid:
            errmsg = "Peer (dbid=[{}]) sent an invalid data.".format(peer.dbid)
            log.warning(errmsg)
            raise ChordException(errmsg)

        distance = mutil.calc_raw_distance(self.engine.node_id, data_id)

        def dbcall():
            with self.engine.node.db.open_session() as sess:
                self.engine.node.db.lock_table(sess, DataBlock)

                q = sess.query(func.count("*")).select_from(DataBlock)
                q = q.filter(DataBlock.data_id == data_id)

                if q.scalar() > 0:
                    # We already have this key.
                    return False, None

                data_block = DataBlock()
                data_block.data_id = data_id
                data_block.distance = distance
                data_block.original_size = 0
                data_block.insert_timestamp = mutil.utc_datetime()

                if dmsg.targeted:
                    data_block.target_key = valid.target_key

                sess.add(data_block)

                # For now we don't track space used by keys.

                sess.commit()

                return True, data_block.id

        r, data_block_id = yield from self.loop.run_in_executor(None, dbcall)

        if not r:
            if log.isEnabledFor(logging.INFO):
                log.info("Not storing key we already have.")

            return False

        if distance > self.engine.furthest_data_block:
            self.engine.furthest_data_block = distance

        if log.isEnabledFor(logging.INFO):
            log.info("Stored key=[{}] as id=[{}]."\
                .format(mbase32.encode(data_id), data_block_id))

        return True

    @asyncio.coroutine
    def _store_synapse(self, peer, data_id, dmsg, need_pruning):
        "Store the Synapse in our local database. Returns True if the data"\
        " was stored, False otherwise."

        peer_dbid = peer.dbid if peer else "<self>"

        synapse = self._check_synapse(dmsg.data)

        if synapse:
            valid = True
        else:
            errmsg = "Peer dbid=[{}] sent an invalid Synapse!"\
                .format(peer_dbid)
            log.warning(errmsg)
            raise ChordException(errmsg)

        synapse_id = enc.generate_ID(synapse.synapse_key)

        def dbcall_chk():
            with self.engine.node.db.open_session() as sess:
                q = sess.query(Synapse)\
                    .filter(\
                        Synapse.keys.any(\
                            and_(\
                                SynapseKey.data_id == synapse_id,\
                                SynapseKey.key_type\
                                    == SynapseKey.KeyType.synapse_key.value)))

                return q.first()

        existing = yield from self.loop.run_in_executor(None, dbcall_chk)

        if not existing:
            return (\
                yield from self.__store_new_synapse(peer_dbid, dmsg, synapse))

        if log.isEnabledFor(logging.INFO):
            log.info(\
                "We already have Synapse (synapse_id=[{}]); adding additional"\
                    " keys -- if applicable."\
                        .format(mbase32.encode(synapse_id)))

        #TODO: YOU_ARE_HERE: As of yet there cannot be keys we didn't store;
        # so we are done here.
        return True

        enc_key = None

        for key in synapse.keys:
            if key.key_type is SynapseKey.KeyType.synapse_key:
                enc_key = enc.decrypt_data_block(key.ekey, synapse.synapse_key)

        if not enc_key:
            errmsg = "Invalid database state; we had this Synapse but not the"\
                " synapse_key in SynapseKey?"
            log.warning(errmsg)
            raise ChordException(errmsg)

        #TODO: YOU_ARE_HERE: Since we store all keys for a Synapse, the only
        # ones that we wouldn't have are synapse_pow possibly and signatures/
        # stamps. So this is to be done when we get to doing that stuff.
        raise ChordException("TODO: YOU_ARE_HERE")

    @asyncio.coroutine
    def __store_new_synapse(self, peer_dbid, dmsg, synapse):
        if len(dmsg.data) > consts.MAX_DATA_BLOCK_SIZE:
            raise ChordException("Synapse is larger than MAX_DATA_BLOCK_SIZE.")

        # We make up a random encryption key, encrypt the Synapse data with
        # that key and store in the Synapse table, encrypt that key with each
        # Synapse key that we are storing and store together in SynapseKey.
        enc_key = os.urandom(64)
        enc_data, b = enc.encrypt_data_block(dmsg.data, enc_key)
        enc_data += b

        distances = []

        def dbcall():
            with self.engine.node.db.open_session() as sess:
                s = Synapse()
                s.data = enc_data
                s.original_size = len(dmsg.data)
                s.insert_timestamp = mutil.utc_datetime()

                s.timestamp = mutil.utc_datetime(synapse.timestamp)
                s.pow_difficulty, direction = synapse.log_distance
                assert direction == 1

                sess.add(s)
                sess.flush()

                def store_key(key, key_type):
                    nonlocal distances

                    sk = SynapseKey()
                    sk.data_id = enc.generate_ID(key)
                    sk.distance = mutil.calc_raw_distance(\
                            self.engine.node_id, sk.data_id)
                    sk.synapse_id = s.id
                    sk.key_type = key_type.value
                    if type(key) is not bytes:
                        key = bytes(key)
                    sk.ekey, b = enc.encrypt_data_block(enc_key, key)

                    sk.timestamp = s.timestamp
                    sk.pow_difficulty = s.pow_difficulty

                    # Because len(key) is multiple of AES blocksize.
                    assert not b

                    sess.add(sk)

                    distances.append(sk.distance)

                store_key(synapse.synapse_key, SynapseKey.KeyType.synapse_key)
                store_key(synapse.synapse_pow, SynapseKey.KeyType.synapse_pow)
                for target_key in synapse.target_keys:
                    store_key(target_key, SynapseKey.KeyType.target_key)
                store_key(synapse.source_key, SynapseKey.KeyType.source_key)

                sess.commit()

        yield from self.loop.run_in_executor(None, dbcall)

        for distance in distances:
            if distance > self.engine.furthest_data_block:
                self.engine.furthest_data_block = distance

        if log.isEnabledFor(logging.INFO):
            #NOTE: We only print IDs not KEYs; so as to prevent entrapment in
            # the log file.
            log.info(\
                "Stored Synapse (synapse_id=[{}], target_id=[{}],"\
                    " source_id=[{}])."\
                        .format(\
                            mbase32.encode(\
                                enc.generate_ID(synapse.synapse_key)),\
                            mbase32.encode(\
                                enc.generate_ID(synapse.target_key)),\
                            mbase32.encode(\
                                enc.generate_ID(synapse.source_key))))

        return True

#TODO: Debug stuff, delete.
#                            assert\
#                                enc.generate_ID(synapse.synapse_pow)\
#                                    == data_id,\
#                                "[{}], [{}], [{}], [{}], [{}]."\
#                                    .format(\
#                                        mbase32.encode(synapse.synapse_key),
#                                        mbase32.encode(\
#                                            enc.generate_ID(\
#                                                synapse.synapse_key)),
#                                        mbase32.encode(synapse.synapse_pow),
#                                        mbase32.encode(\
#                                            enc.generate_ID(\
#                                                synapse.synapse_pow)),
#                                        mbase32.encode(data_id))

    @asyncio.coroutine
    def _store_data(self, peer, data_id, dmsg, need_pruning):
        "Store the data block on disk and meta in the database. Returns True"
        " if the data was stored, False otherwise."

        #TODO: I now realize that this whole method should probably run in a
        # separate thread that is passed to run_in_executor(..), instead of
        # breaking it up into many such calls. Just for efficiency and since
        # there is probably no reason not to.
        #FIXME: This code needs to be fixed to use an additional table,
        # something like DataBlockJournal, which tracks pending deletes or
        # creations, thus ensuring the filesystem is kept in sync, even if
        # crashes, Etc.

        peer_dbid = peer.dbid if peer else "<self>"

        data = dmsg.data
        targeted = dmsg.targeted

        pubkey = None
        if dmsg.pubkey:
            if targeted:
                errmsg = "Targeted updateable key is not implemented."
                log.warning(errmsg)
                raise ChordException(errmsg)

            pubkey = rsakey.RsaKey(dmsg.pubkey)

            data_key = enc.generate_ID(dmsg.pubkey)
            if dmsg.path_hash:
                if log.isEnabledFor(logging.DEBUG):
                    log.debug("path_hash=[{}]."\
                        .format(mbase32.encode(dmsg.path_hash)))
                data_key = enc.generate_ID(data_key + dmsg.path_hash)

            calc_data_id = enc.generate_ID(data_key)

            if data_id != calc_data_id:
                errmsg = "Peer (dbid=[{}]) sent a data_id [{}] that didn't"\
                    " match the updateable key id [{}]!"\
                        .format(peer_dbid, mbase32.encode(data_id),\
                            mbase32.encode(calc_data_id))
                log.warning(errmsg)
                raise ChordException(errmsg)

            hm = bytearray()
            hm += sshtype.encodeBinary(dmsg.path_hash)
            hm += sshtype.encodeMpint(dmsg.version)
            hm += sshtype.encodeBinary(enc.generate_ID(data))

            r = pubkey.verify_ssh_sig(hm, dmsg.signature)
            if not r:
                errmsg = "Peer (dbid=[{}]) sent an invalid signature."\
                    .format(peer_dbid)
                log.warning(errmsg)
                raise ChordException(errmsg)
        else:
            if targeted:
                valid = False

                if data[:16] == MorphisBlock.UUID:
                    tblock, data_key =\
                        self._check_targeted_block(data, data_id=data_id)

                    if tblock:
                        valid = True
                else:
                    assert False, "SynapseS should not get here."
            else:
                # Normal static key uploads get here.
                data_key = enc.generate_ID(data)
                valid = data_id == enc.generate_ID(data_key)

            if not valid:
                errmsg = "Peer (dbid=[{}]) sent a data_id that didn't match"\
                    " the data!".format(peer_dbid)
                log.warning(errmsg)
                raise ChordException(errmsg)

#TODO: Debug stuff, delete.
#        log.warning(\
#            "Storing data for ID=[{}] encrypted with key [{}]."\
#                .format(mbase32.encode(data_id), mbase32.encode(data_key)))

        distance = mutil.calc_raw_distance(self.engine.node_id, data_id)
        original_size = len(data)

        def dbcall():
            with self.engine.node.db.open_session() as sess:
                self.engine.node.db.lock_table(sess, DataBlock)

                old_entry = None
                if pubkey:
                    old_entry = sess.query(DataBlock)\
                        .filter(DataBlock.data_id == data_id)\
                        .first()
                    if old_entry:
                        vint = int(old_entry.version)
                        if vint >= dmsg.version:
                            # We only want to store newer versions.
                            return None, None
                else:
                    q = sess.query(func.count("*")).select_from(DataBlock)
                    q = q.filter(DataBlock.data_id == data_id)

                    if q.scalar() > 0:
                        # We already have this block.
                        return None, None

                if need_pruning:
                    freeable_space = 0
                    blocks_to_prune = []

                    q = sess.query(DataBlock.id, DataBlock.original_size)\
                        .filter(DataBlock.distance > distance)\
                        .filter(DataBlock.original_size != 0)\
                        .order_by(DataBlock.distance.desc())

                    for block in mutil.page_query(q):
                        freeable_space += block.original_size
                        blocks_to_prune.append(block.id)

                        if freeable_space >= original_size:
                            break

                    if freeable_space < original_size:
                        return False, None

                    if log.isEnabledFor(logging.INFO):
                        log.info("Pruning {} blocks to make room."\
                            .format(len(blocks_to_prune)))

                    for anid in blocks_to_prune:
                        sess.query(DataBlock)\
                            .filter(DataBlock.id == anid)\
                            .delete(synchronize_session=False)

                updateable_size_diff = None
                if old_entry:
                    data_block = old_entry
                    assert data_block.data_id == data_id
                    updateable_size_diff =\
                        original_size - data_block.original_size
                else:
                    data_block = DataBlock()
                    data_block.data_id = data_id
                    data_block.distance = distance

                if pubkey:
                    data_block.version = str(dmsg.version)
                    data_block.signature = dmsg.signature

                    a, b = enc.encrypt_data_block(dmsg.pubkey, data_key)
                    data_block.epubkey = a + b
                    data_block.pubkeylen = len(dmsg.pubkey)

                if targeted:
                    if log.isEnabledFor(logging.DEBUG):
                        log.debug("Storing TargetedBlock (target_key=[{}])."\
                            .format(mbase32.encode(tblock.target_key)))
                    # We don't need the following for anything coded yet, but
                    # doing it for now because then we can tell which are
                    # targeted blocks as we may want to have code purge them
                    # with more pressure than normal blocks.
                    data_block.target_key = tblock.target_key

                data_block.original_size = original_size
                data_block.insert_timestamp = mutil.utc_datetime()

                if not old_entry:
                    sess.add(data_block)

                if updateable_size_diff is not None:
                    size_diff = updateable_size_diff
                else:
                    size_diff = original_size

                if need_pruning:
                    size_diff -= freeable_space

                self._update_nodestate(sess, size_diff)

                sess.commit()

                if need_pruning:
                    for anid in blocks_to_prune:
                        try:
                            os.remove(self.engine.node.data_block_file_path\
                                .format(self.engine.node.instance, anid))
                        except FileNotFoundError:
                            if log.isEnabledFor(logging.WARNING):
                                log.warning("FileNotFoundError pruning block"\
                                    " id=[{}]; considered pruned anyways."\
                                        .format(anid))

                return data_block.id, size_diff

        data_block_id, size_diff =\
            yield from self.loop.run_in_executor(None, dbcall)

        if not data_block_id:
            if log.isEnabledFor(logging.INFO):
                if data_block_id is False:
                    log.info("Not storing block we said we would as we"\
                        " can won't free up enough space for it. (Some"\
                        " other block upload must have beaten this one to"\
                        " us.")
                else:
                    log.info("Not storing data that we already have"\
                        " (data_id=[{}])."\
                        .format(mbase32.encode(data_id)))
            return False

        self.engine.node.datastore_size += size_diff

        try:
            if log.isEnabledFor(logging.INFO):
                log.info("Encrypting [{}] bytes of data.".format(len(data)))

            #TODO: If not too much a performance cost: Hash encrypted data
            # block and store hash in the db so we can verify it didn't become
            # corrupted on the filesystem. This is because we will be penalized
            # by the network if we give invalid data when asked for.
            #NOTE: Actually, it should be fine as we can do it in another
            # thread and thus not impact our eventloop thread. We can do it
            # concurrently with encryption!

            # PyCrypto works in blocks, so extra than round block size goes
            # into enc_data_remainder.
            def threadcall():
                return enc.encrypt_data_block(data, data_key)

            enc_data, enc_data_remainder\
                = yield from self.loop.run_in_executor(None, threadcall)

            if log.isEnabledFor(logging.INFO):
                tlen = len(enc_data)
                if enc_data_remainder:
                    tlen += len(enc_data_remainder)
                log.info("Storing [{}] bytes of data.".format(tlen))

            def iocall():
                filename = self.engine.node.data_block_file_path.format(\
                    self.engine.node.instance, data_block_id)

                with open(filename, "wb") as new_file:
                    new_file.write(enc_data)
                    if enc_data_remainder:
                        new_file.write(enc_data_remainder)

            yield from self.loop.run_in_executor(None, iocall)

            if distance > self.engine.furthest_data_block:
                self.engine.furthest_data_block = distance

            if log.isEnabledFor(logging.INFO):
                log.info("Stored data for data_id=[{}] as [{}.blk]."\
                    .format(mbase32.encode(data_id), data_block_id))
            elif log2.isEnabledFor(logging.INFO):
                log2.info("Stored data for data_id=[{}] as [{}.blk]."\
                    .format(mbase32.encode(data_id), data_block_id))

            return True
        except Exception as e:
            log.exception("encrypt/write_to_disk")

            log.warning("There was an exception attempting to store the data"\
                " on disk.")

            def dbcall():
                with self.engine.node.db.open_session() as sess:
                    self.engine.node.db.lock_table(sess, DataBlock)

                    sess.query(DataBlock)\
                        .filter(DataBlock.id == data_block_id)\
                        .delete(synchronize_session=False)

                    # Rule: only update this NodeState row when holding a lock
                    # on the DataBlock table.
                    node_state = sess.query(NodeState)\
                        .filter(NodeState.key == mnnode.NSK_DATASTORE_SIZE)\
                        .first()

                    node_state.value =\
                        str(int(node_state.value) - original_size)

                    sess.commit()

            yield from self.loop.run_in_executor(None, dbcall)

            self.engine.node.datastore_size -= original_size

            def iocall():
                os.remove(self.engine.node.data_block_file_path\
                    .format(self.engine.node.instance, data_block_id))

            try:
                yield from self.loop.run_in_executor(None, iocall)
            except Exception:
                log.exception("os.remove(..)")
                pass

            return False

    def _check_synapse(self, data, data_key=None):
        "Checks if the passed Synapse data is valid; returning the Synapse or"\
        " None if the data was invalid."
        try:
            synapse = syn.Synapse(data)
        except:
            log.exception(\
                "Invalid Synapse; data=[\n{}]."\
                    .format(mutil.hex_dump(data)))
            return None

        if data_key and data_key != synapse.synapse_key\
                and data_key != synapse.synapse_pow:
            log.warning(\
                "Invalid Synapse; data_key != {synapse_key,synapse_pow}"\
                    " ({}/{}/{})."\
                        .format(\
                            mbase32.encode(data_key),\
                            mbase32.encode(synapse.synapse_key),\
                            mbase32.encode(synapse.synapse_pow)))
            return None

        now = mutil.utc_timestamp()
        if synapse.timestamp > now:
            # Refuse to store stuff from the future. :)
            log.warning(\
                "Invalid Synapse; timestamp ([{}]) is in the future (now=[{}]"\
                    ").".format(synapse.timestamp, now))
            return None

        if not synapse.signature:
            # Then it is required to be a POW Synapse.
            dist, direction = synapse.log_distance

            if direction < 0\
                    or dist\
                        > (consts.NODE_ID_BITS - syn.Synapse.MIN_DIFFICULTY):
                log.warning(\
                    "Invalid Synapse; PoW is insufficient ({}/{}/{}/{})."\
                        .format(\
                            direction, dist,\
                            mbase32.encode(synapse.target_key),\
                            mbase32.encode(synapse.synapse_pow)))
                return None

            return synapse

        # Signed Synapse.
        raise Exception()
        #TODO:YOU_ARE_HERE
        #return synapse

    def _check_targeted_block(self, data, data_key=None, data_id=None):
        # Check that the hash(header) matches the data_key we expect.
        header_hash =\
            enc.generate_ID(data[:tb.TargetedBlock.BLOCK_OFFSET])

        if data_key is not None:
            valid_header_hash = header_hash == data_key
        else:
            assert data_id is not None
            data_key = header_hash
            valid_header_hash = enc.generate_ID(data_key) == data_id

        if not valid_header_hash:
            if log.isEnabledFor(logging.WARNING):
                log.warning(\
                    "TargetedData response is invalid (header/hash mismatch)!")
            return False, None

        tblock = tb.TargetedBlock(data)

        # Check that the hash(data) matches the value in the header.
        block_hash = enc.generate_ID(\
            data[tb.TargetedBlock.BLOCK_OFFSET:])

        if block_hash != tblock.block_hash:
            if log.isEnabledFor(logging.WARNING):
                log.warning(\
                    "TargetedData response is invalid (data/header mismatch)!")
            return False, None

        if log.isEnabledFor(logging.DEBUG):
            log.debug("DISTANCE=[{}]."\
                .format(mutil.calc_log_distance(data_key, tblock.target_key)))

        return tblock, data_key

    def _update_nodestate(self, sess, size_diff):
        # Rule: only update this NodeState row when holding a lock on
        # the DataBlock table.
        node_state = sess.query(NodeState)\
            .filter(NodeState.key == mnnode.NSK_DATASTORE_SIZE)\
            .first()

        if not node_state:
            node_state = NodeState()
            node_state.key = mnnode.NSK_DATASTORE_SIZE
            node_state.value = 0
            sess.add(node_state)

        node_state.value = str(int(node_state.value) + size_diff)
