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

        self._setup()

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

        # Open the tunnels with upto max_initial_queries immediate PeerS.
        max_initial_queries = 3
        tunnels = {}
        tasks = []

        for peer_wrapper in self._result_trie:
            if len(tasks) == max_initial_queries:
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

    def process_storage_interest(self, peer_wrapper, msg):
        if log.isEnabledFor(logging.INFO):
            tp = type(peer)
            if tp is Peer:
                #FIXME: YOU_ARE_HERE: What is tunnel data type?
                log.info(\
                    "Peer (tunnel dbid=[{}], path=[{}]) said will_store=[{}]."\
                        .format(\
                            peer_wrapper.tunnel.peer.dbid,\
                            peer_wrapper.path,\
                            msg.will_store))
            else:
                assert tp is mnpeer.Peer
                log.info("Peer (dbid=[{}]) said will_store=[{}]."\
                    .format(peer_wrapper.peer.dbid, msg.will_store))

        peer_wrapper.will_store = msg.will_store

        if msg.will_store:
            #TODO: YOU_ARE_HERE: Track storage cnt and trigger async store
            # process.
            pass

    def process_data_presence(self, peer_wrapper, msg):
        if log.isEnabledFor(logging.INFO):
            tp = type(peer)
            if tp is Peer:
                #FIXME: YOU_ARE_HERE: What is tunnel data type?
                log.info(\
                    "Peer (tunnel dbid=[{}], path=[{}]) said"\
                        " data_present=[{}], first_id=[{}]."\
                            .format(\
                                peer_wrapper.tunnel.peer.dbid,\
                                peer_wrapper.path,\
                                msg.data_present,\
                                mbase32.encode(msg.first_id)))
            else:
                assert tp is mnpeer.Peer
                log.info(\
                    "Peer (dbid=[{}]) said data_present=[{}], first_id=[{}]."\
                        .format(\
                            peer_wrapper.peer.dbid,\
                            msg.will_store,\
                            mbase32.encode(msg.first_id)))

        if self._find_node_msg.significant_bits:
            peer_wrapper.data_present = msg.first_id
        else:
            peer_wrapper.data_present = msg.data_present

        #TODO: YOU_ARE_HERE: Track presence cnt and trigger async get process.

class Tunnel(object):
    def __init__(self, process, peer_wrapper):
        assert type(peer) is mnpeer.Peer

        self.process = process
        self.peer_wrapper = peer_wrapper

        self.peer = peer

        self.loop = process.loop

        self.local_cid = None
        self.queue = None # Input packet queue.

        self.jobs = jobs
        self.task_running = False

        self.task = None

    @asyncio.coroutine
    def run(self):
        "Opens a channel and sends a 'root level' FIND_NODE to the passed"\
        " connected peer, adding results to the passed result_trie, and then"\
        " exiting. The channel is left open so that the caller may route to"\
        " those results through this 'root level' FIND_NODE peer."

        r = yield from self._open_channel()

        if not r:
            #TODO: YOU_ARE_HERE: Signal to processor that a tunnel died.

        r = yield from self._send_find_node()

        if not r:
            #TODO: YOU_ARE_HERE: Signal to processor that a tunnel died.

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
    def _send_find_node(self):
        if log.isEnabledFor(logging.DEBUG):
            log.debug("Sending root level FindNode msg to Peer (dbid=[{}])."\
                .format(peer.dbid))

        self.peer.protocol.write_channel_data(\
            self.local_cid,\
            self.process.find_node_msg.encode())

        pkt = yield from queue.get()

        if not pkt:
            self._set_closed()
            return None

        if self.process._data_mode.value:
            if data_mode is cp.DataMode.store:
                msg = cp.ChordStorageInterest(pkt)
                yield from self.process.process_storage_interest(\
                    self.peer_wrapper, msg)
            elif data_mode is cp.DataMode.get:
                msg = cp.ChordDataPresence(pkt)
                yield from self.process.process_data_presence(\
                    self.peer_wrapper, msg)
            else:
                assert False

            # In data_mode, first packet was data_presence/will_store, and next
            # packet is the PeerList.
            pkt = yield from queue.get()
            if not pkt:
                self._set_closed()
                return None

        #TODO: YOU_ARE_HERE:..

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
