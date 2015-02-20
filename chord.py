import llog

import asyncio
import logging
import os

import packet as mnetpacket
import rsakey
import mn1
import peer
from mutil import hex_dump

log = logging.getLogger(__name__)

class ChordEngine():
    def __init__(self, node):
        self.node = node

        self.server = None
        self.server_protocol = None

        self.pending_connections = []
        self.peers = {} # {(host, port): Peer}.

    def start(self):
        host, port = "127.0.0.1", 5555
        self.server = self.node.get_loop().create_server(self._create_server_protocol, host, port)
        self.node.get_loop().run_until_complete(self.server)
        log.info("Node listening on [{}:{}].".format(host, port))

    def stop(self):
        self.server.close()

    def _create_server_protocol(self):
        ph = mn1.SshServerProtocol(self.node.get_loop())
        ph.set_server_key(self.node.get_node_key())

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
