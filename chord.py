import llog

import asyncio
import logging
import os

import packet as mnetpacket
import rsakey
import mn1
import peer
from mutil import hex_dump
import random

log = logging.getLogger(__name__)

class ChordEngine():
    def __init__(self, node):
        self.node = node

        self.server = None
        self.server_protocol = None

        meta = {"connected": False}
        self.peer_list = [] #[("127.0.0.{}".format(n), 5555, meta) for n in range(1, 100)]
        self.unconnected_peer_cnt = len(self.peer_list)

        self.pending_connections = []
        self.peers = {} # {(host, port): Peer}.

    def start(self):
        host, port = "127.0.0.1", 5555
        self.server = self.node.get_loop().create_server(self._create_server_protocol, host, port)
        self.node.get_loop().run_until_complete(self.server)
        log.info("Node listening on [{}:{}].".format(host, port))

        self._process_connection_count()

    def stop(self):
        self.server.close()

    def _process_connection_count(self):
        desired = 1

        while True:
            cnt = len(self.pending_connections) + len(self.peers)
            if cnt < desired:
                if self._connect_peer():
                    continue
            break

    def _connect_peer(self):
        if self.unconnected_peer_cnt == 0:
            log.info("Insufficient peers to maintain desired connection amount.")
            return False

        while True:
            server = random.choice(self.peer_list)
            # TODO: Optimize for when few servers available.
            if not server[2]["connected"]:
                break;

        loop = self.node.get_loop()
        client = loop.create_connection(self._create_client_protocol, server[0], server[1])

        loop.run_until_complete(client)

        self.unconnected_peer_cnt -= 1

        return True

    def _create_server_protocol(self):
        ph = mn1.SshServerProtocol(self.node.get_loop())
        ph.set_server_key(self.node.get_node_key())

        p = peer.Peer(self)
        p.set_protocol_handler(ph)

        self.pending_connections.append(p)

        return ph

    def _create_client_protocol(self):
        ph = mn1.SshClientProtocol(self.node.get_loop())
        ph.set_client_key(self.node.get_node_key())

        p = peer.Peer(self)
        p.set_protocol_handler(ph)

        self.pending_connections.append(p)

        return ph

    def connection_made(self, peer):
        self.pending_connections.remove(peer)
        addr = peer.get_protocol_handler().get_transport().get_extra_info("peername")
        self.peers[addr] = peer

    def connection_lost(self, peer, exc):
        addr = peer.get_protocol_handler().get_transport().get_extra_info("peername")
        del self.peers[addr]
