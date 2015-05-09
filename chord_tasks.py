import llog

import asyncio
from collections import namedtuple
from datetime import datetime
import logging
import math

from sqlalchemy import func

import bittrie
import chord
import chord_packet as cp
from chordexception import ChordException
from db import Peer, DataBlock
from mutil import hex_string
import enc
import peer as mnpeer

log = logging.getLogger(__name__)

class Counter(object):
    def __init__(self, value=None):
        self.value = value

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
        assert type(peer) is Peer or type(peer) is mnpeer.Peer

        self.peer = peer
        self.path = path
        self.tun_meta = tun_meta
        self.used = False
        self.will_store = None

EMPTY_PEER_LIST_MESSAGE = cp.ChordPeerList(peers=[])
EMPTY_PEER_LIST_PACKET = EMPTY_PEER_LIST_MESSAGE.encode()

class ChordTasks(object):
    def __init__(self, engine):
        self.engine = engine
        self.loop = engine.loop

    @asyncio.coroutine
    def send_node_info(self, peer):
        log.info("Sending ChordNodeInfo message.")

        local_cid, queue =\
            yield from peer.protocol.open_channel("mpeer", True)
        if not queue:
            return

        msg = cp.ChordNodeInfo()
        msg.sender_address = self.engine.bind_address

        peer.protocol.write_channel_data(local_cid, msg.encode())

        data = yield from queue.get()
        if not data:
            return

        msg = cp.ChordNodeInfo(data)
        log.info("Received ChordNodeInfo message.")

        yield from peer.protocol.close_channel(local_cid)

        yield from self.engine._check_update_remote_address(msg, peer)

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
    def send_store_data(self, data):
        # data_id is a double hash due to the anti-entrapment feature.
        data_key = enc.generate_ID(data)
        data_id = enc.generate_ID(data_key)

        yield from self.send_find_node(data_id, data=data)

    @asyncio.coroutine
    def send_find_node(self, node_id, input_trie=None, data=None):
        "Returns found nodes sorted by closets. If data is not None then this"\
        " is really {get/store}_data instead of find_node and nothing is"\
        " returned."

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
            log.info("Performing FindNode (data_packet={}) to a max depth of"\
                " [{}]."\
                .format(data is not None, maximum_depth))

        result_trie = bittrie.BitTrie()

        # Store ourselves to ignore when peers respond with us in their list.
        result_trie[bittrie.XorKey(node_id, self.engine.node_id)] = False

        tasks = []
        used_tunnels = {}
        far_peers_by_path = {}

        for peer in input_trie:
            key = bittrie.XorKey(node_id, peer.node_id)
            vpeer = VPeer(peer)
            # Store immediate PeerS in the result_trie.
            result_trie[key] = vpeer

            if len(tasks) == max_concurrent_queries:
                continue
            if not peer.ready():
                continue

            tun_meta = TunnelMeta(peer)
            used_tunnels[vpeer] = tun_meta

            tasks.append(self._send_find_node(\
                vpeer, node_id, result_trie, tun_meta, data is not None,\
                far_peers_by_path))

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
        sent_data = Counter(0)

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
                    if direct_peers_lower == len(used_tunnels):
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

                pkt = self._generate_relay_packets(row.path, data is not None)

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
                            task_cntr, result_trie, data is not None,\
                            far_peers_by_path, sent_data),\
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

            assert query_cntr.value == 0

            if not task_cntr.value:
                log.info("All tasks exited.")
                break

        if data is not None:
            # If in store_data mode, then send the data to the closest willing
            # nodes that we found.
            if log.isEnabledFor(logging.INFO):
                log.info("Sending data with {} tunnels still open."\
                    .format(task_cntr.value))

            # Just FYI: There might be no tunnels open if we are connected to
            # everyone.

            sent_data.value = 1 # Let tunnel process tasks know.

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

            for row in result_trie:
                if row is False:
                    # Row is ourself.
                    continue
                if not row.will_store:
                    # The node may be close to id, but it says that it does not
                    # want to store the proposed data for whatever reason.
                    continue

                tun_meta = row.tun_meta
                if tun_meta and not tun_meta.queue:
                    # Peer is reached through a tunnel, but the tunnel is
                    # closed.
                    continue

                if log.isEnabledFor(logging.DEBUG):
                    log.debug("Sending StoreData to Peer [{}] and path [{}]."\
                        .format(row.peer.address, row.path))

                msg = cp.ChordStoreData()
                msg.data_id = node_id
                msg.data = data

                if tun_meta:
                    # Then this is a Peer reached through a tunnel.
                    pkt = self._generate_relay_packets(\
                        row.path, True, msg.encode())
                    tun_meta.jobs += 1
                else:
                    # Then this is an immediate Peer.
                    pkt = msg.encode()

                    tun_meta = used_tunnels.get(row)

                    if tun_meta.task_running:
                        # Then this immediate Peer is an open tunnel and will
                        # be handled as described above for case #2.
                        tun_meta.jobs += 1
                    else:
                        # Then this immediate Peer is not an open tunnel and we
                        # will have to start a task to process its DataStored
                        # message.
                        asyncio.async(\
                            self._wait_for_data_stored(\
                                row, tun_meta, query_cntr, done_all),\
                            loop=self.loop)

                tun_meta.peer.protocol.write_channel_data(\
                    tun_meta.local_cid, pkt)

                query_cntr.value += 1

                if query_cntr.value == max_concurrent_queries:
                    break

            if log.isEnabledFor(logging.INFO):
                log.info("Sent StoreData to [{}] nodes."\
                    .format(query_cntr.value))

            yield from done_all.wait()
            done_all.clear()

            assert query_cntr.value == 0

            if log.isEnabledFor(logging.INFO):
                log.info("Finished waiting for StoreData operations; now"\
                    " cleaning up.")

        elif data is not None:
            log.warning("Couldn't send data as all tunnels got closed.")

        # Close everything now that we are done.
        tasks.clear()
        for tun_meta in used_tunnels.values():
            tasks.append(\
                tun_meta.peer.protocol.close_channel(tun_meta.local_cid))
        yield from asyncio.wait(tasks, loop=self.loop)

        if data is not None:
            # In data mode we don't return the peers to save CPU for now.
            return

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

    def _generate_relay_packets(self, path, for_data=False, payload=None):
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
            msg.for_data = for_data
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
    def _send_find_node(self, vpeer, node_id, result_trie, tun_meta, for_data,\
            far_peers_by_path):
        "Opens a channel and sends a 'root level' FIND_NODE to the passed"\
        " connected peer, adding results to the passed result_trie, and then"\
        " exiting. The channel is left open so that the caller may route to"\
        " those results through this 'root level' FIND_NODE peer."

        peer = vpeer.peer

        local_cid, queue =\
            yield from peer.protocol.open_channel("mpeer", True)
        if not queue:
            return

        msg = cp.ChordFindNode()
        msg.node_id = node_id
        msg.for_data = for_data

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Sending root level FindNode msg to Peer (dbid=[{}])."\
                .format(peer.dbid))

        peer.protocol.write_channel_data(local_cid, msg.encode())

        pkt = yield from queue.get()
        if not pkt:
            return

        tun_meta.queue = queue
        tun_meta.local_cid = local_cid

        if for_data:
            msg = cp.ChordStorageInterest(pkt)
            vpeer.will_store = msg.will_store

            pkt = yield from queue.get()
            if not pkt:
                return

        msg = cp.ChordPeerList(pkt)

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Root level FindNode to Peer (id=[{}]) returned {}"\
                " PeerS.".format(peer.dbid, len(msg.peers)))

        idx = 0
        for rpeer in msg.peers:
            if log.isEnabledFor(logging.DEBUG):
                log.debug("Peer (dbid=[{}]) returned PeerList containing Peer"\
                    " (address=[{}]).".format(peer.dbid, rpeer.address))

            vpeer = VPeer(rpeer, [idx], tun_meta)

            key = bittrie.XorKey(node_id, rpeer.node_id)
            result_trie.setdefault(key, vpeer)
            if for_data:
                far_peers_by_path.setdefault((idx,), vpeer)

            idx += 1

    @asyncio.coroutine
    def _process_find_node_relay(\
            self, node_id, tun_meta, query_cntr, done_all, task_cntr,
            result_trie, for_data, far_peers_by_path, sent_data):
        "This method processes an open tunnel's responses, processing the"\
        " incoming messages and appending the PeerS in those messages to the"\
        " result_trie. This method does not close any channel to the tunnel,"\
        " and does not stop processing and exit until the channel is closed"\
        " either by the Peer or by our side outside this method."

        assert type(sent_data) is Counter

        tun_meta.task_running = True

        while True:
            pkt = yield from tun_meta.queue.get()
            if not pkt:
                break

            if sent_data.value\
                    and cp.ChordMessage.parse_type(pkt) != cp.CHORD_MSG_RELAY:
                # This co-routine only expects unwrapped packets in the case
                # we have sent data and are waiting for an ack from the
                # immediate Peer.
                pkts = (pkt,)
            else:
                pkts, path = self.unwrap_relay_packets(pkt, for_data)

            if for_data:
                if sent_data.value:
                    if cp.ChordMessage.parse_type(pkts[0])\
                            != cp.CHORD_MSG_DATA_STORED:
                        # They are too late! We are only looking for DataStored
                        # messages now.
                        continue

                    query_cntr.value -= 1
                    if not query_cntr.value:
                        done_all.set()
                        return

                    continue

                imsg = cp.ChordStorageInterest(pkts[0])
                if imsg.will_store:
                    rvpeer = far_peers_by_path.get(tuple(path))
                    if rvpeer is None:
                        #FIXME: Treat this as attack, Etc.
                        log.warning("Far node not found in dict for path [{}]."\
                            .format(path))

                    rvpeer.will_store = True
                pkt = pkts[1]
            else:
                pkt = pkts[0]

            pmsg = cp.ChordPeerList(pkt)

            log.info("Peer (id=[{}]) returned PeerList of size {}."\
                .format(tun_meta.peer.dbid, len(pmsg.peers)))

            # Add returned PeerS to result_trie.
            idx = 0
            for rpeer in pmsg.peers:
                end_path = tuple(path)
                end_path += (idx,)

                vpeer = VPeer(rpeer, end_path, tun_meta)

                key = bittrie.XorKey(node_id, rpeer.node_id)
                result_trie.setdefault(key, vpeer)

                if for_data:
                    far_peers_by_path.setdefault(end_path, vpeer)

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
                done_all.set()

        if tun_meta.jobs:
            # This tunnel closed while there were still pending jobs, so
            # consider those jobs now completed and subtract them from the
            # count of ongoing jobs.
            query_cntr.value -= tun_meta.jobs
            if not query_cntr.value:
                done_all.set()
            tun_meta.jobs = 0

        # Mark tunnel as closed.
        tun_meta.queue = None
        tun_meta.task_running = False
        # Update counter of open tunnels.
        task_cntr.value -= 1

    def unwrap_relay_packets(self, pkt, for_data):
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
                if packet_type == cp.CHORD_MSG_PEER_LIST:
                    break;
                elif packet_type != cp.CHORD_MSG_RELAY:
                    log.warning("Unexpected packet_type [{}]; ignoring."\
                        .format(packet_type))
                    invalid = True
                    break
            elif len(pkts) > 1:
                # In data mode, PeerS return their storage intent, as well as a
                # list of their connected PeerS.
                if not for_data\
                        or cp.ChordMessage.parse_type(pkts[0])\
                            != cp.CHORD_MSG_STORAGE_INTEREST\
                        or cp.ChordMessage.parse_type(pkts[1])\
                            != cp.CHORD_MSG_PEER_LIST:
                    invalid = True
                # Break as we reached deepest packets.
                break
            else:
                # There should never be an empty relay packet embedded when
                # this method is called.
                invalid = True
                break

        if invalid:
            #FIXME: We should probably update the hostiity tracking of both the
            # Peer and the tunnel Peer instead of just ignoring this invalid
            # state.
            pkts = []

            if for_data:
                pkts.append(cp.ChordStorageInterest())

            tpeerlist = cp.ChordPeerList()
            tpeerlist.peers = []
            pkts.append(tpeerlist.encode())

        return pkts, path

    @asyncio.coroutine
    def _wait_for_data_stored(self, vpeer, tun_meta, query_cntr, done_all):
        while True:
            pkt = yield from tun_meta.queue.get()
            if not pkt:
                break

            msg = cp.ChordDataStored(pkt)
            break

        query_cntr.value -= 1
        if not query_cntr.value:
            done_all.set()

    @asyncio.coroutine
    def process_find_node_request(self, fnmsg, fndata, peer, queue, local_cid):
        "Process an incoming FindNode request."\
        " The channel will be closed before this method returns."

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

        will_store = False
        if fnmsg.for_data:
            # In for_data mode we respond with two packets.
            will_store = self.check_do_want_data(fnmsg.node_id)
            imsg = cp.ChordStorageInterest()
            imsg.will_store = will_store
            log.info("Writing StorageInterest (will_store=[{}]) response."\
                .format(will_store))
            peer.protocol.write_channel_data(local_cid, imsg.encode())

        if not rlist:
            log.info("No nodes closer than ourselves.")
            if not will_store:
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

            if not tun_cntr.value and not will_store:
                # If all the tunnels were closed and we aren't waiting for
                # data, then we clean up and exit.
                yield from self._close_tunnels(rlist)
                yield from peer.protocol.close_channel(local_cid)
                return

            if will_store\
                    and cp.ChordMessage.parse_type(pkt)\
                        == cp.CHORD_MSG_STORE_DATA:
                if log.isEnabledFor(logging.INFO):
                    log.info("Received ChordStoreData packet, storing.")

                rmsg = cp.ChordStoreData(pkt)

                r = yield from self.store_data(peer, rmsg)

                dsmsg = cp.ChordDataStored()
                dsmsg.stored = r

                peer.protocol.write_channel_data(local_cid, dsmsg.encode())
                continue
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
                        fnmsg.for_data),\
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
                    if not fnmsg.for_data:
                        log.warning("Peer [{}] sent a non-empty relay packet"\
                            " with other than a relay packet embedded for"\
                            " tunnel [{}]; skipping."\
                                .format(peer.dbid, rmsg.index))
                        continue
                    # else: It is likely a StoreData message, which is ok.

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
            self, rpeer, rlocal_cid, index, tun_meta, tun_cntr, for_data):
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
                rpeer, rlocal_cid, index, tun_meta, req_cntr, for_data),
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
            self, rpeer, rlocal_cid, index, tun_meta, req_cntr, for_data):
        "Process the responses from a tunnel and relay them back to rpeer."

        while True:
            pkt = yield from tun_meta.queue.get()
            if not tun_meta.jobs:
                return
            if not pkt:
                break

            pkt2 = None
            if for_data and cp.ChordMessage.parse_type(pkt)\
                    != cp.CHORD_MSG_RELAY:
                # First two packets from a newly opened tunnel in for_data mode
                # will be the StorageInterest and PeerList packet.
                pkt2 = yield from tun_meta.queue.get()
                if not tun_meta.jobs:
                    return
                if not pkt2:
                    break

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

    def check_do_want_data(self, data_id):
        #TODO: FIXME: Make this intelligent; based on closeness, diskspace, Etc.
        # Probably something like: if space available, return true. else, return
        # true with probability based upon closeness.
        return True

    @asyncio.coroutine
    def store_data(self, peer, dmsg):
        "Store the data block on disk and meta in the database. Returns True"
        " if the data was stored, False otherwise."

        data = dmsg.data

        data_key = enc.generate_ID(data)
        data_id = enc.generate_ID(data_key)

        if data_id != dmsg.data_id:
            log.warning("Peer (dbid=[{}]) sent a data_id that didn't match"\
                " the data!".format(peer.dbid))

        def dbcall():
            with self.engine.node.db.open_session() as sess:
                self.engine.node.db.lock_table(sess, DataBlock)

                q = sess.query(func.count("*"))
                q = q.filter(DataBlock.data_id == data_id)

                if q.scalar() > 0:
                    # We already have this block.
                    return None

                data_block = DataBlock()
                data_block.data_id = data_id
                data_block.length = len(data)
                data_block.insert_timestamp = datetime.today()

                sess.add(data_block)

                sess.commit()

                return data_block.id

        data_block_id = yield from self.loop.run_in_executor(None, dbcall)

        if not data_block_id:
            if log.isEnabledFor(logging.INFO):
                log.info("Not storing data that we already have"\
                    " (data_id=[{}])."\
                    .format(hex_string(data_id)))
            return False

        try:
            data_block_file_path = "data/store-{}/{}.blk"

            new_file = open(
                data_block_file_path
                    .format(self.engine.node.instance, data_block_id),
                "wb")

            if log.isEnabledFor(logging.INFO):
                log.info("Encrypting [{}] bytes of data.".format(len(data)))

            # PyCrypto works in blocks, so extra than round block size goes
            # into enc_data_remainder.
            enc_data, enc_data_remainder\
                = enc.encrypt_data_block(data, data_key)

            if log.isEnabledFor(logging.INFO):
                log.info("Storing [{}] bytes of data."\
                    .format(len(enc_data) + len(enc_data_remainder)))

            def iocall():
                new_file.write(enc_data)
                new_file.write(enc_data_remainder)

            yield from self.loop.run_in_executor(None, iocall)

            if log.isEnabledFor(logging.INFO):
                log.info("Stored data for data_id=[{}] as [{}.blk]."\
                    .format(data_id, data_block_id))

            return True
        except Exception as e:
            log.exception(e)

            def dbcall():
                with self.engine.node.db.open_session() as sess:
                    sess.query(DataBlock).filter(DataBlock.id == data_block_id)\
                        .delete(synchronize_session=False)
                    sess.commit()

            yield from self.loop.run_in_executor(None, dbcall)

            def iocall():
                os.remove(data_block_file_path)

            try:
                yield from self.loop.run_in_executor(None, iocall)
            except Exception:
                pass

            return False
