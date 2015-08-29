# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
import logging

import packet as mnpacket
import rsakey
import mn1
import mutil
import enc

log = logging.getLogger(__name__)

class Peer():
    def __init__(self, engine, dbpeer=None):
        self.engine = engine

        self.version = None
        self.full_node = False

        self.dbid = None
        self.distance = None
        self.direction = None

        self.address = None

        self.node_key = None
        self.node_id = None
        self.channel_handler = ChannelHandler(self)
        self.connection_handler = ConnectionHandler(self)

        self.connection_coop_lock = asyncio.Lock()

        if dbpeer:
            self.dbid = dbpeer.id
            if dbpeer.pubkey:
                self.node_key = rsakey.RsaKey(dbpeer.pubkey)
            self.node_id = dbpeer.node_id
            self.distance = dbpeer.distance
            self.direction = dbpeer.direction

        self._protocol = None

    @property
    def protocol(self):
        return self._protocol

    @protocol.setter
    def protocol(self, value):
        self._protocol = value

        self._protocol.channel_handler = self.channel_handler
        self._protocol.connection_handler = self.connection_handler

    def ready(self):
        return self._protocol.status is mn1.Status.ready

    def update_distance(self):
        self.distance, self.direction =\
            mutil.calc_log_distance(self.engine.node_id, self.node_id)

    def _peer_authenticated(self, key):
        self.node_key = key

        if not self.node_id:
            self.node_id = enc.generate_ID(self.node_key.asbytes())

        if not self.distance:
            self.update_distance()

class ConnectionHandler():
    def __init__(self, peer):
        self.peer = peer

    def connection_made(self, protocol):
        if log.isEnabledFor(logging.INFO):
            log.info("connection_made(): Peer (dbid=[{}], address=[{}],"\
                " protocol.address=[{}])."\
                .format(self.peer.dbid, self.peer.address, protocol.address))

        if not self.peer.engine.node.tormode:
            self.peer.address = "{}:{}".format(\
                self.peer.protocol.address[0],\
                self.peer.protocol.address[1])

        self.peer.engine.connection_made(self.peer)

    def error_recieved(self, protocol, exc):
        pass

    def connection_lost(self, protocol, exc):
        if log.isEnabledFor(logging.INFO):
            log.info("connection_lost(): Peer (dbid=[{}], address=[{}],"\
                " protocol.address=[{}])."\
                .format(self.peer.dbid, self.peer.address, protocol.address))

        self.peer.engine.connection_lost(self.peer, exc)

    @asyncio.coroutine
    def peer_disconnected(self, protocol, msg):
        self.peer.engine.peer_disconnected(self.peer, msg)

    @asyncio.coroutine
    def peer_authenticated(self, protocol):
        if protocol.server_mode:
            self.peer._peer_authenticated(self.peer.protocol.client_key)
        else:
            self.peer._peer_authenticated(self.peer.protocol.server_key)

        r = yield from self.peer.engine.peer_authenticated(self.peer)

        return r

    @asyncio.coroutine
    def connection_ready(self, protocol):
        log.info("Connection to Peer (dbid=[{}], address=[{}],"\
            " protocol.address=[{}], server_mode=[{}]) is now ready."\
            .format(self.peer.dbid, self.peer.address, protocol.address,\
                protocol.server_mode))

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
    def channel_open_failed(self, protocol, msg):
        r = yield from\
            self.peer.engine.channel_open_failed(self.peer, msg)
        return r

    @asyncio.coroutine
    def channel_opened(self, protocol, channel_type, local_cid, queue):
        yield from\
            self.peer.engine.channel_opened(\
                self.peer, channel_type, local_cid, queue)

    @asyncio.coroutine
    def channel_closed(self, protocol, local_cid):
        yield from self.peer.engine.channel_closed(self.peer, local_cid)

    @asyncio.coroutine
    def channel_request(self, protocol, msg):
        yield from self.peer.engine.channel_request(self.peer, msg)

    @asyncio.coroutine
    def channel_data(self, protocol, local_cid, data):
        if log.isEnabledFor(logging.DEBUG):
            log.debug("Received data: local_cid=[{}], value=[\n{}]."\
                .format(local_cid, mutil.hex_dump(data)))

        # Return value controls if the data gets added to the channel queue.
        r = yield from self.peer.engine.channel_data(\
            self.peer, local_cid, data)
        return r
