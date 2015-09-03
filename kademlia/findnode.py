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

        self._data_mode = None
        self._result_trie = None

        self._setup()

    @asyncio.coroutine
    def run():
        assert len(self.req_id) == chord.NODE_ID_BYTES
        # data_key needs to be bytes for PyCrypto usage later on.
        assert self.data_key is None or type(self.data_key) is bytes,\
            type(self.data_key)

        if self.for_data:
            self.data_mode = cp.DataMode.get if self.data_msg is None\
                else cp.DataMode.store
        else:
            self.data_mode = cp.DataMode.none

        if not self.engine.peers:
            log.info("No connected nodes, unable to send FindNode.")
            return self._generate_fail_response(self.data_mode, self.data_key)

        maximum_depth = 512
        if log.isEnabledFor(logging.INFO):
            log.info("Performing FindNode (node_id=[{}], data_mode={}) to a"\
                " max depth of [{}]."\
                    .format(mbase32.encode(self.req_id), self.data_mode,\
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
        fnmsg.data_mode = self.data_mode
        if data_msg_type is cp.ChordStoreData:
            fnmsg.version = self.data_msg.version
        if self.significant_bits:
            fnmsg.significant_bits = self.significant_bits
            if self.target_key:
                fnmsg.target_key = self.target_key

        # Open the tunnels with upto max_initial_queries immediate PeerS.
        max_initial_queries = 3
        tunnels = []
        tasks = []

        for peer_wrapper in self._result_trie:
            if len(tasks) == max_initial_queries:
                break
            if not peer_wrapper.peer.ready():
                continue

            tunnel = Tunnel(peer_wrapper.peer, self)
            tunnels[peer_wrapper] = tunnel

#            tasks.append(self._send_find_node(\
#                peer_wrapper, fnmsg, result_trie, tun_meta, data_mode,\
#                far_peers_by_path, data_rw))

            tasks.append(asyncio.async(tunnel.run(), loop=self.loop))

            peer_wrapper.used = True

        #TODO: YOU_ARE_HERE: Wait on some event that is signaled when the data
        # is found or sent or whatever.

class Tunnel(object):
    def __init__(self, peer, process):
        assert type(peer) is mnpeer.Peer

        self.peer = peer
        self.find_node_process = process

        self.queue = None
        self.local_cid = None
        self.jobs = jobs
        self.task_running = False

        self.task = None

class PeerWrapper(object):
    def __init__(self, peer=None, tunnel=None, path=None):
        # self.peer can be a mnpeer.Peer for immediate Peer, or a db.Peer for
        # a non immediate (tunneled) Peer.
        assert type(peer) is Peer or type(peer) is mnpeer.Peer

        self.peer = peer
        self.path = path
        self.tunnel = tunnel
        self.used = False
        self.will_store = False
        self.data_present = False
