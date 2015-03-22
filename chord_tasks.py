import llog

import asyncio
from collections import namedtuple
import logging
import math

from sqlalchemy import func

import bittrie
import chord_packet as cp
from chordexception import ChordException
from db import Peer

log = logging.getLogger(__name__)

Counter = namedtuple("Counter",\
    ["value"])
TunnelMeta = namedtuple("TunnelMeta",\
    ["peer", "queue", "local_cid", "jobs"])
VPeer = namedtuple("VPeer",\
    ["peer", "path", "tunnel_meta", "used"])

class ChordTasks(object):

    def __init__(self, engine):
        self.engine = engine
        self.loop = engine.loop

    @asyncio.coroutine
    def _do_stabilize(self):
        maximum_tasks = 3

        def dbcall():
            with self.engine.node.db.open_session() as sess:
                st = sess.query(Peer).statement.with_only_columns(\
                    [func.count('*')])
                return sess.execute(st).scalar()

        known_peer_cnt = yield from self.loop.run_in_executor(None, dbcall)
        maximum_depth = math.log(known_peer_cnt, 2)

        if log.isEnabledFor(logging.INFO):
            log.info("Performing FindNode to a max depth of [{}]."\
                .format(maximum_depth))

        new_nodes = bittrie.BitTrie()

        tasks = []
        used_peers = []

        for peer in self.engine.peer_trie:
            key = bittrie.XorKey(self.engine.node_id, peer.node_id)
            new_nodes[key] = VPeer(peer)

            if len(tasks) == maximum_tasks:
                continue
            if not peer.ready:
                continue

            tun_meta = TunnelMeta(peer, jobs=0)
            used_peers.append(tun_meta)

            tasks.append(self._send_find_node(peer, new_nodes, tun_meta))

        done, pending = yield from asyncio.wait(tasks, loop=self.loop)

        cntr = Counter(0)
        done_all = asyncio.Event()

        for depth in range(1, maximum_depth):
            direct_peers_lower = 0
            for row in new_nodes:
                if row.path is None:
                    # Already asked direct peers, and only asking ones we
                    # haven't asked before.
                    direct_peers_lower += 1
                    if direct_peers_lower == maximum_tasks:
                        # Only deal with results closer than the furthest of
                        # the direct peers we used.
                        break
                    continue

                if row.used:
                    continue

                pkt = None
                for idx in reversed(row.path):
                    msg = cp.ChordRelay()
                    msg.index = idx
                    if pkt:
                        msg.packet = pkt
                    pkt = msg.encode()

                tun_meta = row.tun_meta
                tun_meta.peer.protocol.write_channel_data(\
                    tun_meta.local_cid, pkt)

                row.used = True
                cntr.value += 1
                tun_meta.jobs += 1

                if tun_meta.jobs == 1:
                    # If this is the first relay, then start a process task.
                    asyncio.async(\
                        self._process_find_node_relay(\
                            tun_meta, cntr, done_all, new_nodes))

                if cntr.value == maximum_tasks:
                    break

            if not cntr.value:
                break

            yield from done_all.wait()
            done_all.clear()

        log.info("FindNode search has ended at closest nodes.")

        tasks.clear()
        for tun_meta in used_peers:
            tasks.append(\
                tun_meta.peer.protocol.close_channel(tun_meta.local_cid))
        yield from asyncio.wait(tasks)

        if log.isEnabledFor(logging.INFO):
            for vpeer in new_nodes:
                if not vpeer.path:
                    break
                log.info("Found closer Peer (address={})."\
                    .format(vpeer.peer.address))

        conn_nodes = [vpeer.peer for vpeer in new_nodes if vpeer.path]
        self.engine.add_peers(conn_nodes)

    @asyncio.coroutine
    def _send_find_node(self, peer, result_trie, tun_meta):
        local_cid, queue =\
            yield from peer.protocol.open_channel("mpeer", True)
        if not queue:
            return

        msg = cp.ChordFindNode()
        msg.sender_port = self.engine._bind_port #FIXME: Put elsewhere.
        msg.node_id = self.engine.node_id

        peer.protocol.write_channel_data(local_cid, msg.encode())

        pkt = yield from queue.get()
        if not pkt:
            return

        tun_meta.queue = queue
        tun_meta.local_cid = local_cid

        msg = cp.ChordPeerList(pkt)

        idx = 0
        for rpeer in msg.peers:
            key = bittrie.XorKey(self.engine.node_id, peer.node_id)
            result_trie.setdefault(key, VPeer(rpeer, [idx], tun_meta))
            idx += 1

    @asyncio.coroutine
    def _process_find_node_relay(\
            self, tun_meta, cntr, done_all, result_trie):
        while True:
            pkt = yield from tun_meta.queue.get()
            if not pkt:
                break

            path = []

            while True:
                msg = cp.ChordRelay(pkt)
                path.append(msg.idx)
                pkt = msg.packet
                if cp.ChordMessage.parse_type(pkt) is not cp.CHORD_MSG_RELAY:
                    break

            pmsg = cp.ChordPeerList(pkt)

            for rpeer in pmsg.peers:
                key = bittrie.XorKey(self.engine.node_id, rpeer.node_id)
                result_trie.setdefault(key, [rpeer, path, tun_meta])

            if not tun_meta.jobs:
                log.info(\
                    "Got extra result from tunnel (Peer.id={}, path=[{}])."\
                        .format(tun_meta.peer.dbid, path))
                continue

            tun_meta.jobs -= 1
            cntr.value -= 1
            if not cntr.value:
                done_all.set()
