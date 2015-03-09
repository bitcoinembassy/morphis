import llog

import asyncio
import logging
import os

import packet as mnetpacket
import rsakey
import mn1
from mutil import hex_dump, log_base2_8bit
import chord
import peer
import enc

log = logging.getLogger(__name__)

class Peer():
    def __init__(self, engine, dbpeer=None):
        self.engine = engine

        self.dbid = None
        self.distance = None
        self.direction = None

        self.address = None

        self.node_key = None
        self.node_id = None
        self.channel_handler = ChannelHandler(self)
        self.connection_handler = ConnectionHandler(self)

        if dbpeer:
            self.dbid = dbpeer.id
            self.distance = dbpeer.distance
            self.direction = dbpeer.direction

        self._protocol = None

    @property
    def protocol(self):
        return self._protocol

    @protocol.setter
    def protocol(self, value):
        self._protocol = value

        self._protocol.set_channel_handler(self.channel_handler)
        self._protocol.set_connection_handler(self.connection_handler)

    def _peer_authenticated(self, key):
        self.node_key = key
        self.node_id = enc.generate_ID(self.node_key.asbytes())

        if not self.distance:
            self._calc_distance()

    def _calc_distance(self):
        pid = self.node_id
        nid = self.engine.node_id

        if log.isEnabledFor(logging.DEBUG):
            log.debug("pid=\n[{}], nid=\n[{}].".format(hex_dump(pid),\
                hex_dump(nid)))

        dist = 0
        direction = 0

        for i in range(64): # 64 bytes in 512 bits.
            if pid[i] != nid[i]:
                direction = 1 if pid[i] > nid[i] else -1

                xv = pid[i] ^ nid[i]
                xv = log_base2_8bit(xv)

                dist = 8 * (63 - i) + xv

                break

        self.distance = dist
        self.direction = direction

class ConnectionHandler():
    def __init__(self, peer):
        self.peer = peer

    def connection_made(self, protocol):
        self.peer.address = "{}:{}".format(\
            self.peer.protocol.address[0],\
            self.peer.protocol.address[1])
        self.peer.engine.connection_made(self.peer)

    def error_recieved(self, protocol, exc):
        pass

    def connection_lost(self, protocol, exc):
        self.peer.engine.connection_lost(self.peer, exc)

    @asyncio.coroutine
    def peer_authenticated(self, protocol):
        if protocol.server_mode:
            self.peer._peer_authenticated(self.peer.protocol.client_key)
        else:
            self.peer._peer_authenticated(self.peer.protocol.server_key)

        r = yield from self.peer.engine.peer_authenticated(self.peer)

        return r

    @asyncio.coroutine
    def connection_ready(self):
        yield from self.peer.engine.connection_ready(self.peer)

class ChannelHandler():
    def __init__(self, peer):
        self.peer = peer

    @asyncio.coroutine
    def request_open_channel(self, protocol, message):
        r = yield from\
            self.peer.engine.request_open_channel(self.peer, message)
        return r

    @asyncio.coroutine
    def channel_opened(self, protocol, local_cid):
        yield from\
            self.peer.engine.channel_opened(self.peer, local_cid)

    @asyncio.coroutine
    def data(self, protocol, packet):
        m = mnetpacket.SshChannelDataMessage(packet)
        if log.isEnabledFor(logging.DEBUG):
            log.debug("Received data, recipient_channel=[{}], value=[\n{}].".format(m.recipient_channel, hex_dump(m.data)))
