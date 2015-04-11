import llog

import asyncio
from collections import namedtuple
import logging
import math

from sqlalchemy import func

import bittrie
import chord
import chord_packet as cp
from chordexception import ChordException
from db import Peer
from mutil import hex_string

log = logging.getLogger(__name__)

class Counter(object):
    def __init__(self, value=None):
        self.value = value

class TunnelMeta(object):
    def __init__(self, peer=None, jobs=None):
        self.peer = peer
        self.queue = None
        self.local_cid = None
        self.jobs = jobs

class VPeer(object):
    def __init__(self, peer=None, path=None, tun_meta=None):
        self.peer = peer
        self.path = path
        self.tun_meta = tun_meta
        self.used = False

EMPTY_PEER_LIST_MESSAGE = cp.ChordPeerList(peers=[])
EMPTY_PEER_LIST_PACKET = EMPTY_PEER_LIST_MESSAGE.encode()

class ChordTasks(object):
    def __init__(self, engine):
        self.engine = engine
        self.loop = engine.loop

    @asyncio.coroutine
    def do_stabilize(self):
        if not self.engine.peers:
            log.info("No connected nodes, unable to perform stabilize.")
            return

        # Fetch closest to ourselves.
        closest_nodes = yield from\
            self._do_stabilize(self.engine.node_id, self.engine.peer_trie)

        closest_found_distance =\
            closest_nodes[0].distance if closest_nodes else None

        # Fetch furthest from ourselves.
        node_id = bytearray(self.engine.node_id)
        for i in range(len(node_id)):
            node_id[i] = (~node_id[i]) & 0xFF

        furthest_nodes = yield from self._do_stabilize(node_id)

        if not closest_found_distance:
            closest_found_distance = chord.NODE_ID_BITS
            if furthest_nodes:
                for node in furthest_nodes:
                    if node.distance < closest_found_distance:
                        closest_found_distance = node.distance

            if closest_found_distance is chord.NODE_ID_BITS:
                log.info("Don't know how close a bucket to stop at so not"\
                    " searching inbetween closest and furthest.")
                return

        # Fetch each bucket starting at furthest, stopping when we get to the
        # closest that we found above.
        node_id = bytearray(self.engine.node_id)
        for bit in range(chord.NODE_ID_BITS-1, -1, -1):
            if log.isEnabledFor(logging.INFO):
                log.info("Performing FindNode for bucket [{}]."\
                    .format(bit+1))

            if bit != chord.NODE_ID_BITS-1:
                byte_ = chord.NODE_ID_BYTES - 1 - ((bit+1) >> 3)
                node_id[byte_] ^= 1 << ((bit+1) % 8) # Undo last change.
            byte_ = chord.NODE_ID_BYTES - 1 - (bit >> 3)
            node_id[byte_] ^= 1 << (bit % 8)

            assert self.engine.calc_distance(node_id, self.engine.node_id)[0]\
                == (bit + 1),\
                "calc={}, bit={}, diff={}."\
                    .format(\
                        self.engine.calc_distance(\
                            node_id, self.engine.node_id)[0],\
                        bit + 1,
                        hex_string(\
                            [x ^ y\
                            for x, y\
                                in zip(self.engine.node_id, node_id)])
                        )

            nodes = yield from self._do_stabilize(node_id)

            if not closest_found_distance and not nodes:
                break
            elif bit+1 == closest_found_distance:
                break;

    @asyncio.coroutine
    def _do_stabilize(self, node_id, input_trie=None):
        "Returns found nodes sorted by closets."

        conn_nodes = yield from\
            self.send_find_node(node_id, input_trie)

        if not conn_nodes:
            return

        for node in conn_nodes:
            # Do not trust hearsay node_id; add_peers will recalculate it from
            # the public key.
            node.node_id = None

        yield from self.engine.add_peers(conn_nodes)

        return conn_nodes

    @asyncio.coroutine
    def send_find_node(self, node_id, input_trie=None):
        "Returns found nodes sorted by closets."

        if not self.engine.peers:
            log.info("No connected nodes, unable to send FindNode.")
            return

        if not input_trie:
            input_trie = bittrie.BitTrie()
            for peer in self.engine.peer_trie:
                key = bittrie.XorKey(node_id, peer.node_id)
                input_trie[key] = peer

        max_concurrent_queries = 3

        def dbcall():
            with self.engine.node.db.open_session() as sess:
                st = sess.query(Peer).statement.with_only_columns(\
                    [func.count('*')])
                return sess.execute(st).scalar()

        known_peer_cnt = yield from self.loop.run_in_executor(None, dbcall)
        maximum_depth = int(math.log(known_peer_cnt, 2))

        if log.isEnabledFor(logging.INFO):
            log.info("Performing FindNode to a max depth of [{}]."\
                .format(maximum_depth))

        result_trie = bittrie.BitTrie()

        # Store ourselves to ignore when peers respond with us in their list.
        result_trie[bittrie.XorKey(node_id, self.engine.node_id)] = False

        tasks = []
        used_peers = []

        for peer in input_trie:
            key = bittrie.XorKey(node_id, peer.node_id)
            result_trie[key] = VPeer(peer)

            if len(tasks) == max_concurrent_queries:
                continue
            if not peer.ready():
                continue

            tun_meta = TunnelMeta(peer)
            used_peers.append(tun_meta)

            tasks.append(self._send_find_node(\
                peer, node_id, result_trie, tun_meta))

        if not tasks:
            log.info("Cannot perform FindNode, as we know no closer nodes.")
            return

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Starting {} root level FindNode tasks."\
                .format(len(tasks)))

        done, pending = yield from asyncio.wait(tasks, loop=self.loop)

        query_cntr = Counter(0)
        task_cntr = Counter(0)
        done_all = asyncio.Event(loop=self.loop)

        for depth in range(1, maximum_depth):
            direct_peers_lower = 0
            for row in result_trie:
                if row is False:
                    # Row is ourself. Prevent infinite loops.
                    # Sometimes we are looking closer than ourselves, sometimes
                    # further (stabilize vs other). We could use this to end
                    # the loop maybe, do checks. For now, just ignoring it to
                    # prevent infinite loops.
                    continue
                if row.path is None:
                    # Already asked direct peers, and only asking ones we
                    # haven't asked before.
                    direct_peers_lower += 1
                    if direct_peers_lower == len(used_peers):
                        # Only deal with results closer than the furthest of
                        # the direct peers we used.
                        break
                    continue

                if row.used:
                    continue

                tun_meta = row.tun_meta
                if not tun_meta.queue:
                    continue

                if log.isEnabledFor(logging.DEBUG):
                    log.debug("Sending FindNode to path [{}]."\
                        .format(row.path))

                pkt = None
                for idx in reversed(row.path):
                    msg = cp.ChordRelay()
                    msg.index = idx
                    if pkt:
                        msg.packet = pkt
                    pkt = msg.encode()

                tun_meta.peer.protocol.write_channel_data(\
                    tun_meta.local_cid, pkt)

                row.used = True
                query_cntr.value += 1

                if tun_meta.jobs is None:
                    # If this is the first relay for this tunnel, then start a
                    # _process_find_node_relay task for that tunnel.
                    tun_meta.jobs = 1
                    task_cntr.value += 1
                    asyncio.async(\
                        self._process_find_node_relay(\
                            node_id, tun_meta, query_cntr, done_all,\
                            task_cntr, result_trie),\
                        loop=self.loop)
                else:
                    tun_meta.jobs += 1

                if query_cntr.value == max_concurrent_queries:
                    break

            if not query_cntr.value:
                log.info("FindNode search has ended at closest nodes.")
                break

            yield from done_all.wait()
            done_all.clear()

            if not task_cntr.value:
                log.info("All tasks exited.")
                break

        tasks.clear()
        for tun_meta in used_peers:
            tasks.append(\
                tun_meta.peer.protocol.close_channel(tun_meta.local_cid))
        yield from asyncio.wait(tasks, loop=self.loop)

        if log.isEnabledFor(logging.INFO):
            for vpeer in result_trie:
                if not vpeer or not vpeer.path:
                    continue
                log.info("Found closer Peer (address={})."\
                    .format(vpeer.peer.address))

        rnodes = [vpeer.peer for vpeer in result_trie if vpeer and vpeer.path]

        if log.isEnabledFor(logging.INFO):
            log.info("FindNode found [{}] Peers.".format(len(rnodes)))

        return rnodes

    @asyncio.coroutine
    def _send_find_node(self, peer, node_id, result_trie, tun_meta):
        local_cid, queue =\
            yield from peer.protocol.open_channel("mpeer", True)
        if not queue:
            return

        msg = cp.ChordFindNode()
        msg.sender_address = self.engine._bind_address #FIXME: Put elsewhere.
        msg.node_id = node_id

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Sending root level FindNode msg to Peer (dbid=[{}])."\
                .format(peer.dbid))

        peer.protocol.write_channel_data(local_cid, msg.encode())

        pkt = yield from queue.get()
        if not pkt:
            return

        tun_meta.queue = queue
        tun_meta.local_cid = local_cid

        msg = cp.ChordPeerList(pkt)

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Root level FindNode to Peer (id=[{}]) returned {}"\
                " PeerS.".format(peer.dbid, len(msg.peers)))

        idx = 0
        for rpeer in msg.peers:
            if log.isEnabledFor(logging.DEBUG):
                log.debug("Peer (dbid=[{}]) returned PeerList containing Peer"\
                    " (address=[{}]).".format(peer.dbid, rpeer.address))

            key = bittrie.XorKey(node_id, rpeer.node_id)
            result_trie.setdefault(key, VPeer(rpeer, [idx], tun_meta))
            idx += 1

    @asyncio.coroutine
    def _process_find_node_relay(\
            self, node_id, tun_meta, query_cntr, done_all, task_cntr,
            result_trie):
        while True:
            pkt = yield from tun_meta.queue.get()
            if not pkt:
                break

            path = []

            while True:
                msg = cp.ChordRelay(pkt)
                path.append(msg.index)
                pkt = msg.packet
                packet_type = cp.ChordMessage.parse_type(pkt)
                if packet_type == cp.CHORD_MSG_PEER_LIST:
                    break
                if packet_type != cp.CHORD_MSG_RELAY:
                    log.warning("Unexpected packet_type [{}]."\
                        .format(packet_type))

                    tpeerlist = cp.ChordPeerList()
                    tpeerlist.peers = []
                    pkt = tpeerlist.encode()
                    break

            pmsg = cp.ChordPeerList(pkt)

            log.info("Peer (id=[{}]) returned PeerList of size {}."\
                .format(tun_meta.peer.dbid, len(pmsg.peers)))

            idx = 0
            for rpeer in pmsg.peers:
                end_path = list(path)
                end_path.append(idx)

                key = bittrie.XorKey(node_id, rpeer.node_id)
                result_trie.setdefault(key, VPeer(rpeer, end_path, tun_meta))

                idx += 1

            if not tun_meta.jobs:
                log.info(\
                    "Got extra result from tunnel (Peer.id={}, path=[{}])."\
                        .format(tun_meta.peer.dbid, path))
                continue

            tun_meta.jobs -= 1
            query_cntr.value -= 1
            if not query_cntr.value:
                done_all.set()

        if tun_meta.jobs:
            query_cntr.value -= tun_meta.jobs
            if not query_cntr.value:
                done_all.set()
            tun_meta.jobs = 0

        tun_meta.queue = None

        task_cntr.value -= 1

    @asyncio.coroutine
    def process_find_node_request(self, fnmsg, fndata, peer, queue, local_cid):
        "The channel will be closed before this method returns."

        if fnmsg.sender_address:
            fnmsg.sender_address = ""
            fndata = fnmsg.encode()

        pt = bittrie.BitTrie()

        for cpeer in self.engine.peers.values():
            if cpeer == peer:
                # Don't include asking peer.
                continue

            pt[bittrie.XorKey(fnmsg.node_id, cpeer.node_id)] = cpeer

        # We don't want to deal with further nodes than ourselves.
        pt[bittrie.XorKey(fnmsg.node_id, self.engine.node_id)] = True

        cnt = 3
        rlist = []

        for r in pt:
            if r is True:
                log.info("No more nodes closer than ourselves.")
                break

            if log.isEnabledFor(logging.DEBUG):
                log.debug("nn: {} FOUND: {:7} {:22} node_id=[{}] diff=[{}]"\
                    .format(self.engine.node.instance, r.dbid, r.address,\
                        hex_string(r.node_id), hex_string(\
                            [x ^ y for x, y in\
                                zip(r.node_id, fnmsg.node_id)])))

            rlist.append(r)

            cnt -= 1
            if not cnt:
                break

        # Free memory? We no longer need this, and we may be tunneling for
        # some time.
        pt = None

        if not rlist:
            log.info("No nodes closer than ourselves.")
            yield from peer.protocol.close_channel(local_cid)
            return

        lmsg = cp.ChordPeerList()
        lmsg.peers = rlist

        log.info("Writing PeerList response.")
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

            if not tun_cntr.value:
                # If all the tunnels were closed.
                yield from self._close_tunnels(rlist)
                yield from peer.protocol.close_channel(local_cid)
                return

            rmsg = cp.ChordRelay(pkt)

            if log.isEnabledFor(logging.DEBUG):
                log.debug("Processing request from Peer (id=[{}]) for index"\
                    " [{}].".format(peer.dbid, rmsg.index))

            tun_meta = rlist[rmsg.index]

            if not tun_meta.queue:
                assert not rmsg.packet
                tun_meta.jobs = asyncio.Queue()
                asyncio.async(\
                    self._process_find_node_tunnel(\
                        peer, local_cid, rmsg.index, tun_meta, tun_cntr),\
                    loop=self.loop)
                yield from tun_meta.jobs.put(fndata)
            elif tun_meta.jobs:
                if rmsg.packet is None:
                    log.warning("Peer [{}] sent additional empty relay packet"\
                        " for tunnel [{}]; skipping."\
                            .format(peer.dbid, rmsg.index))
                    continue
                yield from tun_meta.jobs.put(rmsg.packet)
            else:
                if log.isEnabledFor(logging.INFO):
                    log.info("Skipping request for disconnected tunnel [{}]."\
                        .format(rmsg.index))
                yield from self._signal_find_node_tunnel_closed(\
                    peer, local_cid, rmsg.index, 1)

    @asyncio.coroutine
    def _process_find_node_tunnel(\
            self, rpeer, rlocal_cid, index, tun_meta, tun_cntr):
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
                rpeer, rlocal_cid, index, tun_meta, req_cntr),
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
            self, rpeer, rlocal_cid, index, tun_meta, req_cntr):
        while True:
            pkt = yield from tun_meta.queue.get()
            if not tun_meta.jobs:
                return
            if not pkt:
                break

            if log.isEnabledFor(logging.DEBUG):
                log.debug("Relaying response (index={}) from Peer (id=[{}])"\
                    " to Peer (id=[{}])."\
                    .format(index, tun_meta.peer.dbid, rpeer.dbid))

            msg = cp.ChordRelay()
            msg.index = index
            msg.packet = pkt

            rpeer.protocol.write_channel_data(rlocal_cid, msg.encode())

            req_cntr.value -= 1

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
        rmsg.packet = EMPTY_PEER_LIST_PACKET
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
