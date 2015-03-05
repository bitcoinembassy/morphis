import llog

import asyncio
import logging
import os
import random
from functools import partial

from sqlalchemy import func, desc

import packet as mnetpacket
import rsakey
import mn1
import peer
import enc
from db import Peer
from mutil import hex_dump, log_base2_8bit

log = logging.getLogger(__name__)

class ChordEngine():
    def __init__(self, node, bind_address):
        self.node = node
        self.node_id = enc.generate_ID(node.node_key.asbytes())

        self.bind_address = bind_address

        self.running = False
        self.server = None #Task.
        self.server_protocol = None

        self.pending_connections = []
        self.peers = {} # {(host, port): Peer}.

        self.peer_buckets = [[] for i in range(512)]

        self.minimum_connections = 1#10
        self.maximum_connections = 4#64

    def add_peer(self, addr):
        peer = Peer(address=addr, connected=False)

        with self.node.db.open_session() as sess:
            if sess.query(func.count("*")).filter(Peer.address == addr).scalar() > 0:
                log.info("Peer [{}] already in list.".format(addr))
                return

            sess.add(peer)
            sess.commit()

        if self.running:
            self._process_connection_count()

    def start(self):
        self.running = True

        host, port = self.bind_address.split(':')
        self.server = self.node.get_loop().create_server(self._create_server_protocol, host, port)
#        self.node.get_loop().run_until_complete(self.server)
        asyncio.async(self.server, loop=self.node.get_loop())

        log.info("Node listening on [{}:{}].".format(host, port))

        self._process_connection_count()

    def stop(self):
        self.server.close()

    def _process_connection_count(self):
        cnt = len(self.pending_connections) + len(self.peers)
        if cnt >= self.maximum_connections:
            return

        needed = self.maximum_connections - cnt

        with self.node.db.open_session() as sess:
            self.__process_connection_count(sess, needed)

    def __process_connection_count(self, sess, needed):
        np = sess.query(Peer)\
            .filter(Peer.node_id == None, Peer.connected == False)\
            .limit(needed)

        for n in np:
            self._connect_peer(sess, n)
            needed -= 1

        if needed <= 0:
            sess.commit()
            return

        closestdistance = sess.query(func.min_(Peer.distance))\
            .filter(Peer.distance != None)\
            .filter(Peer.distance != 0)\
            .filter(Peer.connected == False)\
            .scalar()

        if not closestdistance:
            sess.commit()
            return

        distance = 512

        while distance > 0:
            bucket_needs = 2 - len(peer_buckets[distance - 1])
            if not bucket_needs:
                continue

            q = sess.query(Peer)\
                .filter(Peer.distance == distance, Peer.connected == None)\
                .order_by(desc(Peer.direction), Peer.node_id)

            np = q.limit(min(needed, bucket_needs))

            for p in np:
                self._connect_peer(sess, p)
                needed -= 1

            if not needed:
                break

            distance -= 1

            if distance < closestdistance:
                break

        sess.commit()

    def _connect_peer(self, sess, peer):
        host, port = peer.address.split(':')

        loop = self.node.get_loop()
        client = loop.create_connection(\
            partial(self._create_client_protocol, peer.id),\
            host, port)

        asyncio.async(client, loop=loop)

        peer.connected = True

        return True

    def _create_server_protocol(self):
        ph = mn1.SshServerProtocol(self.node.get_loop())
        ph.set_server_key(self.node.get_node_key())

        p = peer.Peer(self)
        p.set_protocol_handler(ph)

        self.pending_connections.append(p)

        return ph

    def _create_client_protocol(self, dbid):
        ph = mn1.SshClientProtocol(self.node.get_loop())
        ph.set_client_key(self.node.get_node_key())

        p = peer.Peer(self)
        p.dbid = dbid
        p.set_protocol_handler(ph)

        self.pending_connections.append(p)

        return ph

    def connection_made(self, peer):
        self.pending_connections.remove(peer)
        addr = peer.get_protocol_handler().get_transport().get_extra_info("peername")
        self.peers[addr] = peer

    def connection_lost(self, peer, exc):
        log.debug("connection_lost(): peer.id=[{}].".format(peer.dbid))

        addr = peer.get_protocol_handler().get_transport().get_extra_info("peername")
        del self.peers[addr]

        if not peer.dbid:
            return

        with self.node.db.open_session() as sess:
            dbpeer = sess.query(Peer).get(peer.dbid)
            dbpeer.connected = False
            sess.commit()

    def client_authenticated(self, peer):
        with self.node.db.open_session() as sess:
            dbpeer = sess.query(Peer).filter(Peer.node_id == peer.node_id).first()
            if not dbpeer:
                dbpeer = Peer()
                sess.add(dbpeer)

                dbpeer.node_id = peer.node_id
                dbpeer.pubkey = peer.node_key.asbytes()

                pid = peer.node_id
                nid = self.node_id

                log.info("{},{}".format(len(pid), len(nid)))

                dist = 0
                for i in range(64): # 64 bytes in 512 bits.
                    if pid[i] != nid[i]:
                        dbpeer.direction = 1 if pid[i] > nid[i] else -1

                        xv = pid[i] ^ nid[i]
                        xv = log_base2_8bit(xv)

                        dist = 8 * (63 - i) + xv

                        break

                if dist == 0:
                    dbpeer.direction = 0
                dbpeer.distance = dist

            dbpeer.address = "{}:{}".format(peer.protocol_handler.address[0], peer.protocol_handler.address[1])
            dbpeer.connected = True

            sess.commit()

            peer.dbid = dbpeer.id

            if dbpeer.distance == 0:
                log.info("Peer is us! (Has the same ID!)")
                return False

            return True
