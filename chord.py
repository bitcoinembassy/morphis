import llog

import asyncio
from concurrent import futures
import ipaddress
import logging
from math import sqrt
import os
import random
import sshtype
import struct
from functools import partial
from datetime import datetime, timedelta

from sqlalchemy import Integer, String, text, func, desc, or_

import bittrie
import chord_packet as cp
import chord_tasks as ct
import packet as mnetpacket
import rsakey
import mn1
import peer as mnpeer
import shell
import enc
from db import Peer
from mutil import hex_dump, log_base2_8bit, hex_string


BUCKET_SIZE = 2

ZERO_MEM_512_BIT = bytearray(512>>3)

log = logging.getLogger(__name__)

class ChordEngine():
    def __init__(self, node, bind_address=None):
        self.node = node
        self.node_id = enc.generate_ID(node.node_key.asbytes())

        self.loop = node.loop

        self.running = False
        self.server = None #Task.
        self.server_protocol = None

        self.shells = {}

        self.forced_connects = {} # {id, Peer}
        self.pending_connections = {} # {Task, Peer->dbid}
        self.peers = {} # {address: Peer}.
        self.peer_buckets = [{} for i in range(512)] # [{addr: Peer}]
        self.peer_trie = bittrie.BitTrie() # {node_id, Peer}

        self.minimum_connections = 10
        self.maximum_connections = 72
        self.hard_maximum_connections = self.maximum_connections * 2

        self._bind_address = None
        self._bind_port = None

        self._next_request_id = 0

        self._process_connection_count_handle = None
        self._last_process_connection_count = datetime(1, 1, 1)

    @property
    def bind_address(self):
        return self._bind_address

    @bind_address.setter
    def bind_address(self, value):
        self._bind_address = value
        self._bind_port = int(value.split(':')[1])

    @asyncio.coroutine
    def connect_peer(self, addr):
        "Returns Peer connected to, or dbpeer of already connected Peer,"
        "or None on connection error or invalid address."
        if not check_address(addr):
            log.info("Invalid address [{}], ignoring.".format(addr))
            return None

        dbpeer = yield from self.add_peer(addr, False)

        if not dbpeer:
            # add_peer returns None if the item was already in our db.
            if log.isEnabledFor(logging.INFO):
                log.info("Found [{}] in our database; fetching."\
                    .format(addr))

            def dbcall():
                with self.node.db.open_session() as sess:
                    nonlocal addr
                    dbpeer = sess.query(Peer).filter(Peer.address == addr)\
                        .first()

                    sess.expunge(dbpeer)

                    return dbpeer

            dbpeer = yield from self.loop.run_in_executor(None, dbcall)

            if dbpeer.connected:
                log.info("Not connecting to allready connected Peer ("\
                "id={}, addr=[{}])."
                    .format(dbpeer.id, dbpeer.address))
                return dbpeer

        assert not dbpeer.connected

        self.forced_connects[dbpeer.id] = dbpeer

        r = yield from self._connect_peer(dbpeer)

        return r

    @asyncio.coroutine
    def add_peer(self, addr, process_check_connections=True):
        log.info("Adding peer (addr=[{}]).".format(addr))

        peer = Peer()
        peer.address = addr

        added = yield from self.add_peers([peer], process_check_connections)

        if added:
            return added[0]

    @asyncio.coroutine
    def add_peers(self, peers, process_check_connections=True):
        assert type(peers[0]) is Peer

        log.info("Adding upto {} peers.".format(len(peers)))

        def dbcall():
            with self.node.db.open_session() as sess:
                tlocked = False

                batched = 0
                added = []

                for peer in peers:
                    if not check_address(peer.address):
                        continue

                    if not tlocked:
                        self.node.db.lock_table(sess, Peer)
                        tlocked = True

                    q = sess.query(func.count("*"))

                    if peer.pubkey:
                        assert peer.node_id is None
                        peer.node_id = enc.generate_ID(peer.pubkey)
                        mnpeer.update_distance(self.node_id, peer)
                        q = q.filter(Peer.node_id == peer.node_id)
                    elif peer.address:
                        assert peer.node_id is None
                        q = q.filter(Peer.address == peer.address)

                    if q.scalar() > 0:
                        if log.isEnabledFor(logging.INFO):
                            log.info("Peer [{}] already in list.".format(peer.address))
                        continue

                    peer.connected = False

                    if log.isEnabledFor(logging.INFO):
                        log.info("Adding Peer [{}].".format(peer.address))
                    sess.add(peer)
                    added.append(peer)

                    batched += 1
                    if batched == 10:
                        sess.commit()
                        sess.expunge_all()
                        tlocked = False
                        batched = 0

                if added and tlocked:
                    sess.commit()
                    for dbpeer in added:
                        fetch_id_in_thread = dbpeer.id
                    sess.expunge_all()

                return added

        added = yield from self.loop.run_in_executor(None, dbcall)

        if process_check_connections and added and self.running:
            yield from self._process_connection_count()

        return added

    @asyncio.coroutine
    def start(self):
        self.running = True

        host, port = self._bind_address.split(':')
        self.server = self.loop.create_server(\
            self._create_server_protocol, host, port)

#        self.loop.run_until_complete(self.server)
#        asyncio.async(self.server, loop=self.loop)
        yield from self.server

        log.info("Node listening on [{}:{}].".format(host, port))

        yield from self._process_connection_count()

    def stop(self):
        if self.server:
            self.server.close()

    def _async_process_connection_count(self):
        asyncio.async(self._process_connection_count())

    @asyncio.coroutine
    def _process_connection_count(self):
        cnt = len(self.pending_connections) + len(self.peers)
        if cnt >= self.maximum_connections:
            return

        now = datetime.today()
        if cnt >= self.minimum_connections:
            diff = now - self._last_process_connection_count
            if diff < timedelta(seconds=15):
                return

        self._last_process_connection_count = now

        if self._process_connection_count_handle:
            self._process_connection_count_handle.cancel()

        self._process_connection_count_handle =\
            self.loop.call_later(\
                60, self._async_process_connection_count)

        needed = self.maximum_connections - cnt

        yield from self.__process_connection_count(needed)

    @asyncio.coroutine
    def __process_connection_count(self, needed):
        log.info("Processing connection count.")

        def dbcall():
            with self.node.db.open_session() as sess:
                return sess.query(func.min_(Peer.distance))\
                    .filter(Peer.distance != None)\
                    .filter(Peer.distance != 0)\
                    .filter(Peer.connected == False)\
                    .scalar()

        closestdistance =\
            yield from self.loop.run_in_executor(None, dbcall)

        if not closestdistance:
            return

        pbuffer = []
        connect_futures = []

        fetched = False
        distance = closestdistance
        while True:
            if distance >= 512 + 1:
                if fetched:
                    fetched = False
                    distance = closestdistance
                    continue
                break

            peer_bucket = self.peer_buckets[distance - 1]
            bucket_needs = BUCKET_SIZE - len(peer_bucket)
            if bucket_needs <= 0:
                distance += 1
                continue

            def dbcall():
                with self.node.db.open_session() as sess:
                    grace = datetime.today() - timedelta(minutes=5)

                    q = sess.query(Peer)\
                        .filter(Peer.distance == distance,\
                            Peer.connected == False,\
                            or_(Peer.last_connect_attempt == None,\
                                Peer.last_connect_attempt < grace))\
                        .order_by(desc(Peer.direction), Peer.node_id)\
                        .limit(bucket_needs * 2)

                    r = q.all()

                    sess.expunge_all()

                    return r

            if len(pbuffer) < 10:
                rs = yield from self.loop.run_in_executor(None, dbcall)

                if not len(rs):
                    distance += 1
                    continue

                fetched = True

                for dbpeer in rs:
                    pbuffer.append(dbpeer)

                if len(pbuffer) < 10:
                    distance += 1
                    continue

            while len(connect_futures) < 7:
                dbpeer = pbuffer.pop()
                connect_c =\
                    asyncio.async(self._connect_peer(dbpeer), loop=self.loop)

                connect_futures.append(connect_c)

            connected, pending = yield from asyncio.wait(\
                connect_futures, loop=self.loop,\
                return_when=futures.FIRST_COMPLETED)

            connect_futures = list(pending)

            for task in connected:
                if task.result():
                    needed -= 1

            if needed <= 0:
                log.info("Connected to requested amount of PeerS.")
                if connect_futures:
                    yield from asyncio.wait(connect_futures, loop=self.loop)
                log.info("Finished connecting.")
                return

            distance += 1

        log.info("No more available PeerS to fetch.")
        if connect_futures:
            yield from asyncio.wait(connect_futures, loop=self.loop)
        log.info("Finished connecting all PeerS we could find.")

    @asyncio.coroutine
    def _connect_peer(self, dbpeer):
        log.info("Connecting to peer (id={}, addr=[{}]).".format(dbpeer.id,\
            dbpeer.address))

        host, port = dbpeer.address.split(':')

        peer = mnpeer.Peer(self, dbpeer)

        client = self.loop.create_connection(\
            partial(self._create_client_protocol, peer),\
            host, port)

        def dbcall(dbpeer):
            with self.node.db.open_session() as sess:
                self.node.db.lock_table(sess, Peer)
                dbpeer = sess.query(Peer).get(dbpeer.id)
                if dbpeer.connected:
                    if log.isEnabledFor(logging.DEBUG):
                        log.debug(\
                            "Peer [{}] connected to us in the mean time."\
                            .format(dbpeer.id))
                    return False

                dbpeer.connected = True
                dbpeer.last_connect_attempt = datetime.today()
                sess.commit()
                return True

        r = yield from self.loop.run_in_executor(None, dbcall, dbpeer)

        if not r:
            return None

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

            yield from self.loop.run_in_executor(None, dbcall, dbpeer)

            if peer.protocol:
                peer.protocol.close()

            return None

        if dbpeer.node_id:
            if not self.add_to_peers(peer):
                log.info("Already connected to Peer (id={}).".format(peer.dbid))
                peer.protocol.close()
                return None

        return peer

    def _create_server_protocol(self):
        ph = mn1.SshServerProtocol(self.loop)
        ph.server_key = self.node.node_key

        p = mnpeer.Peer(self)
        p.protocol = ph

#        self.pending_connections.append(p)

        return ph

    def _create_client_protocol(self, peer):
        ph = mn1.SshClientProtocol(self.loop)
        ph.client_key = self.node.node_key

        if peer.node_key:
            ph.server_key = peer.node_key

        peer.protocol = ph

#        self.pending_connections.append(peer)

        return ph

    def connection_made(self, peer):
        pass

    def connection_lost(self, peer, exc):
        asyncio.async(self._connection_lost(peer, exc), loop=self.loop)

    @asyncio.coroutine
    def _connection_lost(self, peer, exc):
        self.remove_from_peers(peer)

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

        yield from peer.connection_coop_lock.acquire()
        try:
            yield from self.loop.run_in_executor(None, dbcall)
        finally:
            peer.connection_coop_lock.release()

    @asyncio.coroutine
    def peer_disconnected(self, peer, msg):
        pass

    @asyncio.coroutine
    def peer_authenticated(self, peer):
        log.info("Peer (dbid={}) has authenticated.".format(peer.dbid))

        if peer.protocol.status is not mn1.Status.new:
            log.info("Peer disconnected.")
            return False

        add_to_peers = None

        yield from peer.connection_coop_lock.acquire()
        try:
            r, add_to_peers = yield from self._peer_authenticated(peer)
        finally:
            peer.connection_coop_lock.release()

        if not r or peer.protocol.status is not mn1.Status.new:
            return False

        r = self.forced_connects.pop(peer.dbid, None)
        if not r:
            r = self.is_peer_connection_desirable(peer)
            if not r:
                log.info("Peer [dbid={}] connection unwanted, disconnecting."\
                    .format(peer.dbid))
                return False, False

        if add_to_peers:
            r = self.add_to_peers(peer)
            if not r:
                return False

        # Do any init that we delay until after auth to save cpu/mem/Etc.
        self.tasks = ct.ChordTasks(self)

        return True

    @asyncio.coroutine
    def _peer_authenticated(self, peer):
        add_to_peers = True

        if peer.dbid:
            # This would be an outgoing connection; and thus this dbid does
            # for sure exist in the database.
            def dbcall():
                with self.node.db.open_session() as sess:
                    dbpeer = sess.query(Peer).get(peer.dbid)

                    if not dbpeer.node_id:
                        # Then it was a manually initiated connection (and no
                        # public key was specified).
                        self.node.db.lock_table(sess, Peer)
                        odbpeer = sess.query(Peer)\
                            .filter(Peer.node_id == peer.node_id).first()

                        if odbpeer:
                            sess.delete(dbpeer)

                            if odbpeer.connected:
                                log.info("We were already connected to"\
                                    " Peer (id={}), dropping manual"\
                                    " Peer (id={}) connection."\
                                    .format(odbpeer.id, dbpeer.id))
                                sess.commit()
                                sess.expunge(dbpeer)
                                return False, False
                            else:
                                odbpeer.connected = True

                            log.info("We already knew (id={}) about"\
                                " manual added peer (id={})."\
                                .format(odbpeer.id, dbpeer.id))
                            dbpeer = odbpeer
                            peer.dbid = dbpeer.id
                        else:
                            dbpeer.node_id = peer.node_id
                            dbpeer.pubkey = peer.node_key.asbytes()

                            dbpeer.distance = peer.distance
                            dbpeer.direction = peer.direction

                        if dbpeer.distance == 0:
                            log.info("Peer is us! (Has the same ID!)")
                            sess.delete(dbpeer)
                            sess.commit()
                            return False, False

                        sess.commit()
                        sess.expunge(dbpeer)
                        return True, True
                    else:
                        # Then we were trying to connect to a specific node_id.
                        if dbpeer.node_id != peer.node_id:
                            # Then the node we reached is not the node we were
                            # trying to connect to.
                            dbpeer.connected = False
                            sess.commit()
                            return False, False

                        sess.expunge(dbpeer)
                        return True, False # We already did when connecting.

            r, r2 = yield from self.loop.run_in_executor(None, dbcall)
            if not r:
                return False, False

            if not r2:
                add_to_peers = False
        else:
            # This would be an incoming connection.
            def dbcall():
                with self.node.db.open_session() as sess:
                    self.node.db.lock_table(sess, Peer)
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
                            return False, None

                        dbpeer.address = peer.address

                        sess.add(dbpeer)
                    else:
                        # Known Peer has connected to us.
                        if dbpeer.distance == 0:
                            log.warning("Found ourselves in the Peer table!")
                            log.info("Peer is us! (Has the same ID!)")
                            dbpeer.connected = False
                            sess.delete(dbpeer)
                            sess.commit()
                            return False, None

                        if dbpeer.connected:
                            log.info("Already connected to Peer, disconnecting redundant connection.")
                            return False, None

                        host, port = dbpeer.address.split(':')
                        if host != peer.protocol.address[0]:
                            log.info("Remote Peer host has changed, updating our db record.")
                            dbpeer.address = "{}:{}".format(\
                            peer.protocol.address[0],\
                            port)

                    dbpeer.connected = True

                    sess.commit()

                    fetch_id_in_thread = dbpeer.id

                    sess.expunge(dbpeer)

                    return True, dbpeer

            r, dbpeer = yield from self.loop.run_in_executor(None, dbcall)
            if not r:
                return False, False

            peer.dbid = dbpeer.id

            if peer.address != dbpeer.address:
                peer.address = dbpeer.address

        return True, add_to_peers

    def add_to_peers(self, peer):
        existing = self.peers.setdefault(peer.address, peer)
        if existing is not peer:
            log.error("Somehow we are trying to connect to an address [{}] already connected!".format(peer.address))
            return False
        self.peer_buckets[peer.distance - 1][peer.address] = peer

        xorkey = bittrie.XorKey(self.node_id, peer.node_id)
        self.peer_trie[xorkey] = peer

        return True

    def remove_from_peers(self, peer):
        self.peers.pop(peer.address, None)
        if peer.distance:
            self.peer_buckets[peer.distance - 1].pop(peer.address, None)

        if peer.node_id:
            xorkey = bittrie.XorKey(self.node_id, peer.node_id)
            self.peer_trie.pop(xorkey, None)

    def is_peer_connection_desirable(self, peer):
        peercnt = len(self.peers)

        if peer.protocol.address[0].startswith("127."):
            if peer.protocol.remote_banner.startswith("SSH-2.0-OpenSSH"):
                return True

        if peercnt >= self.hard_maximum_connections:
            return False

        if peer.protocol.server_mode:
            return True

        bucket = self.peer_buckets[peer.distance - 1]

        if len(bucket) < BUCKET_SIZE:
            return True

        # Otherwise check that the node_id is closer than all others.
        xorkey = bittrie.XorKey(self.node_id, peer.node_id)

        cnt = 0
        none_started = False
        for closer_node in self.peer_trie.find(xorkey, False):
            if not closer_node:
                none_started = True
                continue
#            elif not none_started and peer.protocol.server_mode:
#                # Outgoing connections are expected to be in the peer_trie.
#                log.info("Peer already connected, undesirable.")
#                return False

            if closer_node.distance != peer.distance:
                # No more closer ones.
                return True

            cnt += 1
            if cnt == BUCKET_SIZE:
                log.info(\
                    "Peer is further than BUCKET_SIZE connected PeerS,"\
                    " undesirable.")
                return False

        return True

    @asyncio.coroutine
    def connection_ready(self, peer):
        server_mode = peer.protocol.server_mode

        log.info("Connection to Peer (dbid={}, server_mode={}) is now ready."\
            .format(peer.dbid, server_mode))

        if server_mode:
            # TODO: Do checks, limits, and stuff.
            return;

        # Client requests a GetPeers upon connection.
        asyncio.async(self.tasks._do_stabilize(), loop=self.loop)

    @asyncio.coroutine
    def request_open_channel(self, peer, req):
        if req.channel_type == "mpeer":
            return True
        elif req.channel_type == "session":
            return peer.protocol.address[0] == "127.0.0.1"
        return False

    @asyncio.coroutine
    def channel_open_failed(self, peer, msg):
        pass

    @asyncio.coroutine
    def channel_opened(self, peer, channel_type, local_cid, queue):
        if not channel_type:
            # channel_type is None when the we initiated the channel.
            return

        if channel_type == "mpeer":
            asyncio.async(\
                self._process_chord_packet(peer, local_cid, queue),\
                loop=self.loop)
            return
        elif channel_type == "session":
            self.shells[local_cid] =\
                shell.Shell(self.loop, peer, local_cid, queue)
            return

    @asyncio.coroutine
    def channel_closed(self, peer, local_cid):
        self.shells.pop(local_cid, None)

        pass

    @asyncio.coroutine
    def channel_request(self, peer, msg):
        if msg.request_type == "shell":
            shell = self.shells[msg.recipient_channel]
            if not shell:
                return
            asyncio.async(shell.cmdloop(), loop=self.loop)
        elif msg.request_type == "exec":
            shell = self.shells[msg.recipient_channel]
            if not shell:
                return
            l, cmd = sshtype.parseString(msg.payload)
            asyncio.async(self._shell_exec(shell, cmd), loop=self.loop)

    @asyncio.coroutine
    def _shell_exec(self, shell, cmd):
        result = yield from shell.onecmd(cmd)
        shell.flush()
        yield from shell.peer.protocol.close_channel(shell.local_cid)

    @asyncio.coroutine
    def channel_data(self, peer, local_cid, data):
        # Return False means to let data go into channel queue.
        return False

    @asyncio.coroutine
    def _process_chord_packet(self, peer, local_cid, queue):
        while True:
            log.info("Waiting for chord packet.")
            r = yield from\
                self.__process_chord_packet(peer, queue, local_cid)
            if not r:
                break

    @asyncio.coroutine
    def __process_chord_packet(self, peer, queue, local_cid):
        "Returns True to stop processing the queue."

        data = yield from queue.get()
        if not data:
            return True

        log.info("Processing chord packet.")

        if log.isEnabledFor(logging.DEBUG):
            log.debug("data=\n[{}].".format(hex_dump(data)))

        packet_type = cp.ChordMessage.parse_type(data)
        if packet_type == cp.CHORD_MSG_GET_PEERS:
            log.info("Received CHORD_MSG_GET_PEERS message.")
            msg = cp.ChordGetPeers(data)

            if peer.protocol.server_mode:
                omsg = cp.ChordGetPeers()
                omsg.sender_port = self._bind_port

                peer.protocol.write_channel_data(local_cid, omsg.encode())

            self._check_update_remote_port(msg, peer)

            pl = list(self.peers.values())
            while True:
                cnt = len(pl)

                msg = cp.ChordPeerList()
                msg.peers = pl[:min(25, cnt)]

                peer.protocol.write_channel_data(local_cid, msg.encode())

                if cnt <= 25:
                    break;

                pl = pl[25:]

        elif packet_type == cp.CHORD_MSG_PEER_LIST:
            log.info("Received CHORD_MSG_PEER_LIST message.")
            msg = cp.ChordPeerList(data)
            if not msg.peers:
                log.debug("Ignoring empty PeerList.")
                return
            yield from self.add_peers(msg.peers)
        elif packet_type == cp.CHORD_MSG_FIND_NODE:
            log.info("Received CHORD_MSG_FIND_NODE message.")
            msg = cp.ChordFindNode(data)

            self._check_update_remote_port(msg, peer)

            r = yield from\
                self.tasks.process_find_node_request(\
                    msg, data, peer, queue, local_cid)

            return True

# Example of non-working db code. Sqlite seems to break when order by contains
# any bitwise operations. (It just returns the rows in order of id.)
#            def dbcall():
#                with self.node.db.open_session() as sess:
#                    t = text(\
#                        "SELECT id, address FROM peer ORDER BY"\
#                        " (~(node_id&:r_id))&(node_id|:r2_id) DESC"\
#                        " LIMIT :lim")
#
#                    st = t.bindparams(r_id = msg.node_id, r2_id = msg.node_id,\
#                            lim = BUCKET_SIZE)\
#                        .columns(id=Integer, address=String)
#
#                    rs = sess.connection().execute(st)
#
#                    for r in rs:
#                        log.info("nn: {} FOUND: {} {}".format(self.node.instance, r.id, r.address))
#
#            yield from self.loop.run_in_executor(None, dbcall)
        else:
            log.warning("Ignoring unrecognized packet (packet_type=[{}])."\
                .format(packet_type))

    @asyncio.coroutine
    def _check_update_remote_port(self, msg, peer):
        if not msg.sender_port:
            return

        host, port = peer.address.split(':')

        if int(port) != msg.sender_port:
            log.info(\
                "Remote Peer said port [{}] has changed, updating our records"\
                " [{}].".format(msg.sender_port, port))

            self.peers.pop(peer.address, None)
            self.peer_buckets[peer.distance - 1].pop(peer.address, None)

            peer.address = "{}:{}".format(host, msg.sender_port)

            self.peers[peer.address] = peer
            self.peer_buckets[peer.distance - 1][peer.address] = peer

            def dbcall():
                with self.node.db.open_session() as sess:
                    dbp = sess.query(Peer).get(peer.dbid);
                    dbp.address = peer.address
                    sess.commit()

            yield from self.loop.run_in_executor(None, dbcall)

def check_address(address):
    try:
        host, port = address.split(':')
        ipaddress.ip_address(host)
        return True
    except:
        if log.isEnabledFor(logging.DEBUG):
            log.debug("Address [{}] is not acceptable.".format(address))
        return False
