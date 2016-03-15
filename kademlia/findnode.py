import llog

import asyncio
import logging

import chord

log = logging.getLogger(__name__)

class FindNodeProcess(object):
    def __init__(self, engine):
        self.engine = engine
        self.loop = engine.loop

        self.req_id = None
        self.significant_bits = None
        self.input_trie = None
        self.for_data = False
        self.data_msg = None
        self.data_key = None
        self.path_hash = None
        self.targeted = False
        self.target_key = None
        self.scan_only = False
        self.retry_factor = 1

        self._find_node_msg = None
        self._data_mode = None
        self._result_trie = None

        self._waiting_on_get_data = False
        self._data_present_peers = []

    @asyncio.coroutine
    def run(self):
        assert len(self.req_id) == chord.NODE_ID_BYTES
        # data_key needs to be bytes for PyCrypto usage later on.
        assert self.data_key is None or type(self.data_key) is bytes,\
            type(self.data_key)

        if self.for_data:
            self._data_mode = cp.DataMode.get if self.data_msg is None\
                else cp.DataMode.store
        else:
            self._data_mode = cp.DataMode.none

        if not self.engine.peers:
            log.info("No connected nodes, unable to send FindNode.")
            return self._generate_fail_response(self._data_mode, self.data_key)

        maximum_depth = 512
        if log.isEnabledFor(logging.INFO):
            log.info("Performing FindNode (req_id=[{}], data_mode={}) to a"\
                " max depth of [{}]."\
                    .format(mbase32.encode(self.req_id), self._data_mode,\
                        maximum_depth))

        if self.input_trie:
            self._result_trie = self.input_trie
        else:
            # Build a BitTrie of all connected PeerS, sorted by their distance
            # to the req_id.
            self._result_trie = bittrie.BitTrie()
            for peer in self.engine.peers.values():
                if not peer.full_node:
                    continue
                key = bittrie.XorKey(self.req_id, peer.node_id)
                self._result_trie[key] = PeerWrapper(peer)

        # Store ourselves to ignore when peers respond with us in their list.
        #FIXME: Can do this where we add PeerS instead more efficiently.
        key = bittrie.XorKey(self.req_id, self.engine.node_id)
        self._result_trie[key] = False

        data_msg_type = type(self.data_msg)

        # Build the FindNode message that we are going to send.
        fnmsg = cp.ChordFindNode()
        fnmsg.node_id = self.req_id
        fnmsg.data_mode = self._data_mode
        if data_msg_type is cp.ChordStoreData:
            fnmsg.version = self.data_msg.version
        if self.significant_bits:
            fnmsg.significant_bits = self.significant_bits
            if self.target_key:
                fnmsg.target_key = self.target_key
        self._find_node_msg = fnmsg

        # Open the tunnels with upto max_initial_tunnels immediate PeerS.
        max_initial_tunnels = 3
        tunnels = {}
        tasks = []

        for peer_wrapper in self._result_trie:
            if len(tasks) == max_initial_tunnels:
                break
            if not peer_wrapper.peer.ready():
                continue

            tunnel = Tunnel(self, peer_wrapper.peer)
            tunnels[peer_wrapper] = tunnel

#            tasks.append(self._send_find_node(\
#                peer_wrapper, fnmsg, result_trie, tun_meta, data_mode,\
#                far_peers_by_path, data_rw))

            tasks.append(asyncio.async(tunnel.run(), loop=self.loop))

            peer_wrapper.used = True

        #TODO: YOU_ARE_HERE: Wait on some event that is signaled when the data
        # is found or sent or whatever.

    @asyncio.continue
    def _notify_data_presence(self, peer_wrapper):
        self._data_present_peers.append(peer_wrapper)

        if self._waiting_on_get_data:
            return

        self._send_get_data(peer_wrapper)

    @asyncio.coroutine
    def _send_get_data(self, peer_wrapper):
        assert not self._waiting_on_get_data
        self._waiting_on_get_data = True

        peer_wrapper.tunnel.peer.channel.write_packet


class Tunnel(object):
    def __init__(self, process, peer_wrapper):
        self.process = process
        self.peer_wrapper = peer_wrapper

        peer = peer_wrapper.peer
        self.peer = peer
        assert type(peer) is mnpeer.Peer

        self.loop = process.loop

        self.local_cid = None
        self.queue = None # Input packet queue.

        self.jobs = jobs
        self.task_running = False

        self.task = None

        self._result_trie = None
        self._peers_by_path = {} # {path, PeerWrapper}.

    @asyncio.coroutine
    def run(self):
        "Opens a channel and sends a 'root level' FIND_NODE to the passed"\
        " connected peer, adding results to the passed result_trie, and then"\
        " exiting. The channel is left open so that the caller may route to"\
        " those results through this 'root level' FIND_NODE peer."

        r = yield from self._open_channel()
        if not r:
            #TODO: YOU_ARE_HERE: Signal to processor that a tunnel died.

        r = yield from self._send_and_process_root_find_nodes()
        if not r:
            #TODO: YOU_ARE_HERE: Signal to processor that a tunnel died.

        yield from self._send_next_find_nodes()

        yield from self._process_responses()

    @asyncio.coroutine
    def _open_tunnel(self):
        try:
            self.local_cid, self.queue =\
                yield from asyncio.wait_for(\
                    self.peer.protocol.open_channel("mpeer", True),\
                    timeout=30,\
                    loop=self.loop)
            return True
        except asyncio.TimeoutError:
            if log.isEnabledFor(logging.INFO):
                log.info("Timeout opening channel to Peer (dbid=[{}])."\
                    .format(self.peer.dbid))
            self.peer.protocol.close()
            return False

    def _set_closed(self):
        self.local_cid = None

    @asyncio.coroutine
    def _send_and_process_root_find_nodes(self):
        if log.isEnabledFor(logging.DEBUG):
            log.debug("Sending root level FindNode msg to Peer (dbid=[{}])."\
                .format(self.peer.dbid))

        self.peer.protocol.write_channel_data(\
            self.local_cid,\
            self.process.find_node_msg.encode())

        pkt = yield from self.queue.get()

        if not pkt:
            self._set_closed()
            return None

        if self.process._data_mode.value:
            # If data_mode, then first packet is not the PeerList.
            if data_mode is cp.DataMode.store:
                msg = cp.ChordStorageInterest(pkt)
                yield from self.process._process_storage_interest(\
                    self.peer_wrapper, msg)
            elif data_mode is cp.DataMode.get:
                msg = cp.ChordDataPresence(pkt)
                yield from self.process._process_data_presence(\
                    self.peer_wrapper, msg)
            else:
                assert False

            # In data_mode, first packet was data_presence/will_store, and next
            # packet is the PeerList.
            pkt = yield from self.queue.get()
            if not pkt:
                self._set_closed()
                return None

        # Process the PeerList response.
        msg = cp.ChordPeerList(pkt)

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Root level FindNode to Peer (id=[{}]) returned {}"\
                " PeerS.".format(self.peer.dbid, len(msg.peers)))

        req_id = self.process.req_id

        idx = 0
        for rpeer in msg.peers:
            if log.isEnabledFor(logging.DEBUG):
                log.debug("Peer (dbid=[{}]) returned PeerList containing Peer"\
                    " (address=[{}]).".format(peer.dbid, rpeer.address))

            path = (idx,)
            pw = PeerWrapper(rpeer, self, path)
            key = bittrie.XorKey(req_id, rpeer.node_id)

            r = self.processor._result_trie.setdefault(key, pw)
            if r:
                continue

            self._result_trie.setdefault(key, pw)
            self._peers_for_path[path] = pw

        return True

    @asyncio.coroutine
    def _send_next_find_nodes(self):
        concurrent_requests = 3
        req = 0

        for pw in self._result_trie:
            if pw.used:
                # We've already sent to this Peer.
                # For the first run through, we will only send to closer and
                # closer nodes.
                break

            pw.used = True

            pkt = self._generate_relay_packets(pw.path)
            self.peer.protocol.write_channel_data(self.local_cid, pkt)

            req += 1
            if req == concurrent_requests:
                break

    @asyncio.coroutine
    def _process_responses(self):
        while True:
            pkt = yield from self.queue.get()
            if not pkt:
                return

            pkt_type = cp.ChordMessage.parse_type(pkts[0])

            if pkt_type != cp.CHORD_MSG_RELAY:
                #TODO: YOU_ARE_HERE: Can get a DataResponse or DataStored.
                raise ChordException("Peer (dbid=[{}]) sent an unexpected"\
                    " unwrapped packet of type [{}]."\
                        .format(self.peer.dbid, pkt_type))

            if log.isEnabledFor(logging.DEBUG):
                log.debug("Unwrapping ChordRelay packet.")

            pkts, path = self._unwrap_relay_packets(pkt, data_mode)
            path = tuple(path)

            pw = self._peers_by_path[path]

            for pkt in pkts:
                pkt_type = cp.ChordMessage.parse(pkt)

                if pkt_type == cp.CHORD_MSG_PEER_LIST:
                    r = self._process_peer_list(pw, path, pkt)
                    if r:
                        self._send_next_find_nodes()
                elif pkt_type == cp.CHORD_MSG_DATA_PRESENCE:
                    msg = cp.ChordDataPresence(pkt)
                    yield from self.process._process_data_presence(\
                        self.peer_wrapper, msg)
                elif pkt_type == cp.CHORD_MSG_STORAGE_INTEREST:
                    msg = cp.ChordStorageInterest(pkt)
                    yield from self.process._process_storage_interest(\
                        self.peer_wrapper, msg)
                else:
                    #TODO: YOU_ARE_HERE: Can get a DataResponse or DataStored.
                    log.debug("Peer (tunnel dbid=[{}], path=[{}]) returned"\
                        " an unexpected packet of type [{}]; ignoring."\
                        .format(self.peer.dbid, path, pkt_type))
                    continue

    def _process_peer_list(self, source_pw, path, pkt):
        "Processes a PeerList response packet from a tunneled Peer."\
        "Returns the count of new PeerS for this FindNode process."

        if pw.peer_list_packet_count == 1:
            log.info(\
                "Peer (id=[{}]) sent too many PeerList pkts."\
                    .format(mbase32.encode(pw.peer.node_id)))
            return 0
        else:
            assert pw.peer_list_packet_count == 0
            pw.peer_list_packet_count = 1

        msg = cp.ChordPeerList(pkt)

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Peer (tunnel dbid=[{}], path=[{}]) returned {} PeerS."\
                .format(self.peer.dbid, path, len(msg.peers)))

        req_id = self.process.req_id

        added_peers = 0
        idx = 0
        for rpeer in msg.peers:
            if log.isEnabledFor(logging.DEBUG):
                log.debug("Peer (tunnel dbid=[{}], path=[{}]) returned"\
                    " PeerList containing Peer (address=[{}])."\
                        .format(self.peer.dbid, path, rpeer.address))

            end_path = path + (idx,)

            pw = PeerWrapper(rpeer, self, end_path)
            key = bittrie.XorKey(req_id, rpeer.node_id)

            r = self.processor._result_trie.setdefault(key, pw)
            if r:
                continue

            self._result_trie.setdefault(key, pw)
            self._peers_by_path[path] = pw

            added_peers += 1

        return added_peers

    @asyncio.coroutine
    def _process_storage_interest(self, peer_wrapper, msg):
        if log.isEnabledFor(logging.INFO):
            tp = type(peer)
            if tp is Peer:
                log.info(\
                    "Peer (tunnel dbid=[{}], path=[{}]) said will_store=[{}]."\
                        .format(\
                            self.peer.dbid,\
                            peer_wrapper.path,\
                            msg.will_store))
            else:
                assert tp is mnpeer.Peer
                log.info("Peer (dbid=[{}]) said will_store=[{}]."\
                    .format(self.peer.dbid, msg.will_store))

        peer_wrapper.will_store = msg.will_store

        if msg.will_store:
            #TODO: YOU_ARE_HERE: Track storage cnt and trigger async store
            # process.
            pass

    @asyncio.coroutine
    def _process_data_presence(self, peer_wrapper, msg):
        if log.isEnabledFor(logging.INFO):
            tp = type(peer)
            if tp is Peer:
                log.info(\
                    "Peer (tunnel dbid=[{}], path=[{}]) said"\
                        " data_present=[{}], first_id=[{}]."\
                            .format(\
                                self.peer.dbid,\
                                peer_wrapper.path,\
                                msg.data_present,\
                                mbase32.encode(msg.first_id)))
            else:
                assert tp is mnpeer.Peer
                log.info(\
                    "Peer (dbid=[{}]) said data_present=[{}], first_id=[{}]."\
                        .format(\
                            self.peer.dbid,\
                            msg.will_store,\
                            mbase32.encode(msg.first_id)))

        if self.process._find_node_msg.significant_bits:
            peer_wrapper.data_present = msg.first_id
        else:
            peer_wrapper.data_present = msg.data_present

        yield from self.process._notify_data_presence(peer_wrapper)

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

        #FIXME: TODO: ChordRelay should be modified to allow a message payload
        # instead of the byte 'packet' payload. This way it can recursively
        # call encode() on the payloads that way appending data each iteration
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

    def _unwrap_relay_packets(self, pkt, data_mode):
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
                else:
                    # Break as we reached deepest packet.
                    break
            else:
                # In data mode, PeerS return their storage intent, as well as a
                # list of their connected PeerS.
                # Break as we reached deepest packets.
                break

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Unwrapped {} packets with path=[{}]."\
                .format(len(pkts), path))

        return pkts, path

class PeerWrapper(object):
    def __init__(self, peer=None, tunnel=None, path=None):
        # self.peer can be a mnpeer.Peer for immediate Peer, or a db.Peer for
        # a non immediate (tunneled) Peer.
        assert type(peer) in (Peer, mnpeer.Peer)

        self.peer = peer
        self.path = path
        self.tunnel = tunnel
        self.used = False
        self.will_store = False
        self.data_present = False

        self.peer_list_packet_count = 0
