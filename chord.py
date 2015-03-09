import llog

import asyncio
import logging
import os
import random
from functools import partial
from datetime import datetime, timedelta

from sqlalchemy import func, desc, or_

import packet as mnetpacket
import rsakey
import mn1
import peer as mnpeer
import enc
from db import Peer
from mutil import hex_dump, log_base2_8bit

log = logging.getLogger(__name__)

class ChordEngine():
    def __init__(self, node, bind_address=None):
        self.node = node
        self.node_id = enc.generate_ID(node.node_key.asbytes())

        self.bind_address = None

        self.running = False
        self.server = None #Task.
        self.server_protocol = None

        self.pending_connections = {} # {Task, Peer->dbid}
        self.peers = {} # {address: Peer}.

        self.peer_buckets = [{} for i in range(512)] # [{addr: Peer}]

        self.minimum_connections = 1#10
        self.maximum_connections = 4#64

    @asyncio.coroutine
    def add_peer(self, addr):
        log.info("Adding peer (addr=[{}]).".format(addr))

        def dbcall():
            with self.node.db.open_session() as sess:
                peer = Peer(address=addr, connected=False)

                if sess.query(func.count("*")).filter(Peer.address == addr).scalar() > 0:
                    log.info("Peer [{}] already in list.".format(addr))
                    return False

                sess.add(peer)
                sess.commit()

                return True

        r = yield from self.node.loop.run_in_executor(None, dbcall)

        if r and self.running:
            yield from self._process_connection_count()

    @asyncio.coroutine
    def start(self):
        self.running = True

        host, port = self.bind_address.split(':')
        self.server = self.node.loop.create_server(\
            self._create_server_protocol, host, port)

#        self.node.loop.run_until_complete(self.server)
#        asyncio.async(self.server, loop=self.node.loop)
        yield from self.server

        log.info("Node listening on [{}:{}].".format(host, port))

        yield from self._process_connection_count()

    def stop(self):
        self.server.close()

    @asyncio.coroutine
    def _process_connection_count(self):
        cnt = len(self.pending_connections) + len(self.peers)
        if cnt >= self.maximum_connections:
            return

        needed = self.maximum_connections - cnt

        yield from self.__process_connection_count(needed)

    @asyncio.coroutine
    def __process_connection_count(self, needed):
        # First connect to any unconnected PeerS that are in the database with
        # a null node_id. Such entries had to be added manually; thus we should
        # listen to the user and try them out.
        def dbcall():
            with self.node.db.open_session() as sess:
                return sess.query(Peer)\
                    .filter(Peer.node_id == None, Peer.connected == False)\
                    .limit(needed).all()

        np = yield from self.node.loop.run_in_executor(None, dbcall)

        for dbp in np:
            peer = yield from self._connect_peer(dbp)
            if peer:
                needed -= 1

        if needed <= 0:
            return

        # If we still need PeerS, then we now use our Chord algorithm.

        def dbcall():
            with self.node.db.open_session() as sess:
                return sess.query(func.min_(Peer.distance))\
                    .filter(Peer.distance != None)\
                    .filter(Peer.distance != 0)\
                    .filter(Peer.connected == False)\
                    .scalar()

        closestdistance =\
            yield from self.node.loop.run_in_executor(None, dbcall)

        if not closestdistance:
            return

        distance = 512

        while distance > 0:
            peer_bucket = self.peer_buckets[distance - 1]
            bucket_needs = 2 - len(peer_bucket)
            if not bucket_needs:
                continue

            def dbcall():
                with self.node.db.open_session() as sess:
                    grace = datetime.today() - timedelta(minutes=5)

                    q = sess.query(Peer)\
                        .filter(Peer.distance == distance,\
                            Peer.connected == False,\
                            or_(Peer.last_connect_attempt == None,\
                                Peer.last_connect_attempt < grace))\
                        .order_by(desc(Peer.direction), Peer.node_id)

                    np = q.limit(min(needed, bucket_needs))
                    return q.all()

            np = yield from self.node.loop.run_in_executor(None, dbcall)

            if len(np):
                bucket_needs = len(np)

                for dbp in np:
                    peer = yield from self._connect_peer(dbp)

                    if not peer:
                        continue

                    existing = peer_bucket.setdefault(dbp.address, peer)
                    if existing is not peer:
                        log.error("Somehow we are trying to connect to an address [{}] already connected! [{}][{}]".format(dbp.address, existing, peer))

                    needed -= 1
                    bucket_needs -= 1

                if not needed:
                    break

                if bucket_needs:
                    continue

            distance -= 1

            if distance < closestdistance:
                log.info("No more available PeerS to connect.")
                break

    @asyncio.coroutine
    def _connect_peer(self, dbpeer):
        log.info("Connecting to peer (id={}, addr=[{}]).".format(dbpeer.id,\
            dbpeer.address))

        host, port = dbpeer.address.split(':')

        loop = self.node.loop

        peer = mnpeer.Peer(self, dbpeer)

        client = loop.create_connection(\
            partial(self._create_client_protocol, peer),\
            host, port)

        def dbcall(dbpeer):
            with self.node.db.open_session() as sess:
                dbpeer = sess.query(Peer).get(dbpeer.id)
                dbpeer.connected = True
                dbpeer.last_connect_attempt = datetime.today()
                sess.commit()

        yield from self.node.loop.run_in_executor(None, dbcall, dbpeer)

        try:
            yield from client
        except Exception as ex:
            log.info("Connection to Peer (dbid=[{}]) failed: {}: {}"\
                .format(dbpeer.id, type(ex), ex))

            # An exception on connect; update db, Etc.
            def dbcall(dbpeer):
                with self.node.db.open_session() as sess:
                    dbpeer = sess.query(Peer).get(dbpeer.id)
                    dbpeer.connected = False

                    sess.commit()

            yield from self.node.loop.run_in_executor(None, dbcall, dbpeer)

            return None

        return peer

    def _create_server_protocol(self):
        ph = mn1.SshServerProtocol(self.node.loop)
        ph.server_key = self.node.get_node_key()

        p = mnpeer.Peer(self)
        p.set_protocol_handler(ph)

#        self.pending_connections.append(p)

        return ph

    def _create_client_protocol(self, peer):
        ph = mn1.SshClientProtocol(self.node.loop)
        ph.client_key = self.node.get_node_key()

        peer.set_protocol_handler(ph)

#        self.pending_connections.append(peer)

        return ph

    def connection_made(self, peer):
        self.peers[peer.address] = peer

    def connection_lost(self, peer, exc):
        asyncio.async(self._connection_lost(peer, exc), loop=self.node.loop)

    @asyncio.coroutine
    def _connection_lost(self, peer, exc):
        log.debug("connection_lost(): peer.id=[{}].".format(peer.dbid))

        addr = peer.get_protocol_handler().get_transport().get_extra_info("peername")
        del self.peers[peer.address]
        self.peer_buckets[peer.distance - 1].pop(peer.address)

        if not peer.dbid:
            return

        def dbcall():
            with self.node.db.open_session() as sess:
                dbpeer = sess.query(Peer).get(peer.dbid)
                if not dbpeer:
                    # Might have been deleted.
                    return;
                dbpeer.connected = False
                sess.commit()

        yield from self.node.loop.run_in_executor(None, dbcall)

    @asyncio.coroutine
    def peer_authenticated(self, peer):
        log.info("Peer (dbid={}) has authenticated.".format(peer.dbid))

        add_to_bucket = True

        if peer.dbid:
            # This would be an outgoing connection; and thus this dbid does
            # for sure exist in the database.
            def dbcall():
                with self.node.db.open_session() as sess:
                    dbpeer = sess.query(Peer).get(peer.dbid)

                    if not dbpeer.node_id:
                        # Then it was a manually initiated connection (and no
                        # public key was specified).
                        dbpeer.node_id = peer.node_id
                        dbpeer.pubkey = peer.node_key.asbytes()

                        dbpeer.distance = peer.distance
                        dbpeer.direction = peer.direction

                        if dbpeer.distance == 0:
                            log.info("Peer is us! (Has the same ID!)")
                            sess.delete(dbpeer)
                            sess.commit()
                            return False

                        sess.commit()
                    else:
                        # Then we were trying to connect to a specific node_id.
                        add_to_bucket = False # We already did when connecting.
                        if dbpeer.node_id != peer.node_id:
                            # Then the node we reached is not the node we were
                            # trying to connect to.
                            dbpeer.connected = False
                            sess.commit()
                            return False

                    return True

            r = yield from self.node.loop.run_in_executor(None, dbcall)
            if not r:
                return False
        else:
            # This would be an incoming connection.
            def dbcall():
                with self.node.db.open_session() as sess:
                    dbpeer = sess.query(Peer)\
                        .filter(Peer.node_id == peer.node_id).first()

                    if not dbpeer:
                        # An incoming connection from an unknown Peer.
                        dbpeer = Peer()
                        dbpeer.node_id = peer.node_id
                        dbpeer.pubkey = peer.node_key.asbytes()

                        dbpeer.distance = peer.distance
                        dbpeer.direction = peer.direction

                        if dbpeer.distance == 0:
                            log.info("Peer is us! (Has the same ID!)")
                            return False

                        dbpeer.address = peer.address
                        sess.add(dbpeer)
                    else:
                        # Known Peer has connected to us.
                        if dbpeer.distance == 0:
                            log.warning("Found ourselves in the Peer table!")
                            log.info("Peer is us! (Has the same ID!)")
                            dbpeer.connected = False
                            sess.commit()
                            return False

                        if dbpeer.connected:
                            log.info("Already connected to Peer, disconnecting redundant connection.")
                            return False

                        host, port = dbpeer.address.split(':')
                        if host != peer.protocol_handler.address[0]:
                            log.info("Remote Peer host has changed, updating our db record.")
                            dbpeer.address = "{}:{}".format(\
                                peer.protocol_handler.address[0],\
                                port)

                    dbpeer.connected = True

                    sess.commit()

                    return True, dbpeer.id

            r, dbid = yield from self.node.loop.run_in_executor(None, dbcall)
            if not r:
                return False

            if not peer.dbid:
                peer.dbid = dbid

        if add_to_bucket:
            existing = self.peer_buckets[peer.distance - 1]\
                .setdefault(peer.address, peer)
            if existing is not peer:
                log.error("Somehow we are trying to connect to an address [{}] already connected!".format(peer.address))

        return True

    @asyncio.coroutine
    def connection_ready(self, peer):
        server_mode = peer.protocol_handler.server_mode

        log.info("Connection to Peer (dbid={}, server_mode={}) is now ready."\
            .format(peer.dbid, server_mode))

        if server_mode:
            # TODO: Do checks, limits, and stuff.
            return;

        yield from peer.protocol_handler.open_channel("mpeer")

    @asyncio.coroutine
    def request_open_channel(self, peer, req):
        if req.channel_type != "mpeer":
            return False

        return True

    @asyncio.coroutine
    def open_channel(self, peer, req, sender_channel):
        pass
