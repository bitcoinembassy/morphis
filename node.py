#!/usr/bin/python3
# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import argparse
import asyncio
import logging
import os

from sqlalchemy import update, func

import packet as mnetpacket
import rsakey
import mn1
import mutil
import chord
import peer
import db

# NodeState keys.
NSK_DATASTORE_SIZE = "datastore_size"

# The following is limited by max packet size. We could either increase that
# size, violating the SSH spec, which I don't want to do because then it would
# be easier to identify Morphis traffic. Instead we would need to modify the
# dataMessage task code to handle a single block in multiple StoreData packets.
MAX_DATA_BLOCK_SIZE = 32768

log = logging.getLogger(__name__)

loop = None
nodes = []
node_callback = None

dumptasksonexit = False
maalstroom_enabled = True

class Node():
    def __init__(self, loop, instance_id=None, dburl=None):
        self.chord_engine = None
        self.loop = loop

        self.instance = instance_id
        if instance_id:
            self.instance_postfix = "-{}".format(instance_id)
        else:
            self.instance_postfix = ""

        self.node_key = None

        self.data_block_path = "data/store-{}"
        self.data_block_file_path =\
            self.data_block_path + "/{}.blk"

        self.datastore_max_size = 0 # In bytes.
        self.datastore_size = 0 # In bytes.

        if dburl:
            self.db = db.Db(loop, dburl, 'n' + str(instance_id))
        else:
            self.db = db.Db(\
                loop,\
                "sqlite:///data/morphis{}.sqlite".format(self.instance_postfix))
        self._db_initialized = False

        self.bind_address = None
        self.unsecured_transport = None

        self.shell_enabled = True
        self.eval_enabled = False

        self.web_devel = False

        self.seed_node_enabled = True

        self.morphis_version = None

        self.ready = asyncio.Event(loop=loop)

        self.tormode = False
        self.offline_mode = False

    @property
    def all_nodes(self):
        global nodes
        return nodes

    @property
    def engine(self):
        return self.chord_engine

    @asyncio.coroutine
    def init_db(self):
        if self._db_initialized:
            log.debug("The database is already initialized.")
            return

        if not os.path.exists("data"):
            log.info("The 'data' directory was missing; creating.")
            os.makedirs("data")

        self.db.init_engine()

        yield from self.db.ensure_schema()

        self._db_initialized = True

    @asyncio.coroutine
    def init_store(self, max_size, reinit):
        self.datastore_max_size = max_size

        d = self.data_block_path.format(self.instance)
        if not os.path.exists(d):
            if log.isEnabledFor(logging.INFO):
                log.info("Creating data store directory [{}].".format(d))
            os.makedirs(d)

            # Update the database to reflect the filesystem if reinit is True.
            def dbcall():
                with self.db.open_session() as sess:
                    st = sess.query(db.DataBlock).statement.with_only_columns(\
                        [func.count('*')])
                    cnt =  sess.execute(st).scalar()

                    if cnt and not reinit:
                        return False

                    stmt =\
                        update(db.NodeState, bind=self.db.engine)\
                            .where(db.NodeState.key == NSK_DATASTORE_SIZE)\
                            .values(value=0)
                    sess.execute(stmt)

                    sess.query(db.DataBlock).delete(synchronize_session=False)

                    sess.commit()

                    return True

            r = yield from self.loop.run_in_executor(None, dbcall)

            if not r:
                errmsg = "Database still had DataBlock rows;"\
                    " refusing to start in an inconsistent state."\
                    " If you meant to delete your datastore then"\
                    " rerun with --reinitds."
                log.warning(errmsg)
                raise Exception(errmsg)

        else:
            def dbcall():
                with self.db.open_session(True) as sess:
                    node_state = sess.query(db.NodeState)\
                        .filter(db.NodeState.key == NSK_DATASTORE_SIZE)\
                        .first()

                    if node_state:
                        datastore_size = int(node_state.value)
                    else:
                        datastore_size = 0

                    max_distance = sess.query(db.DataBlock.distance)\
                        .order_by(db.DataBlock.distance.desc())\
                        .first()

                    if max_distance:
                        max_distance = max_distance[0]
                    else:
                        max_distance = b""

                    if log.isEnabledFor(logging.INFO):
                        log.info("max_distance=[{}]."\
                            .format(mutil.hex_string(max_distance)))

                    return datastore_size, max_distance

            self.datastore_size, self.chord_engine.furthest_data_block =\
                yield from self.loop.run_in_executor(None, dbcall)

        assert type(self.chord_engine.furthest_data_block) is bytes

    @asyncio.coroutine
    def start(self):
        if not self._db_initialized:
            yield from self.init_db()

        self.chord_engine.bind_address = self.bind_address

        def dbcall():
            with self.db.open_session() as sess:
                # Grab Peer count.
                st = sess.query(db.Peer)\
                    .statement.with_only_columns(\
                        [func.count('*')])
                peer_cnt = sess.execute(st).scalar()

                # Clear out connected state.
                sess.execute(update(db.Peer, bind=self.db.engine)\
                    .values(connected=False, last_connect_attempt=None))

                # Our calc_log_distance calculation was broken in older
                # versions! Code in db.py clears out this column if the db was
                # the older version to signal this code to execute..
                peer = sess.query(db.Peer).filter(db.Peer.node_id != None)\
                    .first()
                if peer and peer.distance is None:
                    for peer in sess.query(db.Peer)\
                            .filter(db.Peer.node_id != None).all():
                        peer.distance, direction =\
                            mutil.calc_log_distance(\
                                self.engine.node_id, peer.node_id)

                sess.commit()

                return peer_cnt

        log.info("Clearing out connected state from Peer table.")
        self.chord_engine.last_db_peer_count =\
            yield from self.loop.run_in_executor(None, dbcall)

        if not self.chord_engine.last_db_peer_count\
                and not self.chord_engine.connect_peers\
                and self.seed_node_enabled:
            self.chord_engine.connect_peers = [\
                "162.252.242.77:4250",\
                "45.79.172.110:4252",\
                "139.162.130.68:4252"]

            if log.isEnabledFor(logging.INFO):
                log.info("No PeerS in our database nor specified as a"\
                    " parameter; using seednodes [{}]."\
                        .format(self.chord_engine.connect_peers))

        yield from self.chord_engine.start()

        self.ready.set()

    def stop(self):
        if self.chord_engine:
            self.chord_engine.stop()

    def load_key(self):
        self.node_key = self._load_key()

    def _load_key(self):
        key_filename = "data/node_key-rsa{}.mnk".format(self.instance_postfix)

        if os.path.exists(key_filename):
            log.info("Node private key file found, loading.")
            return rsakey.RsaKey(filename=key_filename)
        else:
            log.info("Node private key file missing, generating.")
            node_key = rsakey.RsaKey.generate(bits=4096)
            node_key.write_private_key_file(key_filename)
            return node_key

    def init_chord(self):
        self.chord_engine = chord.ChordEngine(self)

def main():
    global loop, nodes, dumptasksonexit

    loop = asyncio.get_event_loop()

    asyncio.async(_main(), loop=loop)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        log.warning("Got KeyboardInterrupt; shutting down.")
        if dumptasksonexit or log.isEnabledFor(logging.DEBUG):
            try:
                for task in asyncio.Task.all_tasks(loop=loop):
                    print("Task [{}]:".format(task))
                    task.print_stack()
            except Exception:
                log.exception("Exception printing tasks.")
    except Exception:
        log.exception("loop.run_forever() threw:")

    for node in nodes:
        node.stop()
    loop.close()

    if maalstroom_enabled:
        import maalstroom
        maalstroom.shutdown()

    log.info("Shutdown.")

@asyncio.coroutine
def _main():
    global loop

    try:
        yield from __main()
    except BaseException as e:
        if type(e) is not SystemExit:
            log.exception("__main()")
        loop.stop()

@asyncio.coroutine
def __main():
    global loop, nodes, dumptasksonexit, maalstroom_enabled

    print("Launching node.")
    log.info("Launching node.")

    parser = argparse.ArgumentParser()
    parser.add_argument("--nn", type=int,\
        help="Node instance number.")
    parser.add_argument("--addpeer",\
        help="Add a node to peer list.", action="append")
    parser.add_argument("--bind",\
        help="Specify bind address (host:port). The default is \":4250\";"\
            " which will listen on all interfaces on port 4250.")
    parser.add_argument("--cleartexttransport", action="store_true",\
        help="Clear text transport and no authentication.")
    parser.add_argument("--dbpoolsize", type=int,\
        help="Specify the maximum amount of database connections.")
    parser.add_argument("--dburl",\
        help="Specify the database url to use.")
    parser.add_argument("--dm", action="store_true",\
        help="Disable Maalstroom server.")
    parser.add_argument("--dmdmail", action="store_true",\
        help="Disable Maalstroom Dmail UI and API.")
    parser.add_argument("--dmupload", action="store_true",\
        help="Disable Maalstroom Upload UI and API.")
    parser.add_argument("--disableautopublish", action="store_true",\
        help="Disable Dmail auto-publish check/publish mechanism.")
    parser.add_argument("--disableautoscan", action="store_true",\
        help="Disable Dmail auto-scan scanning.")
    parser.add_argument("--disable-csrf-check", action="store_true",\
        help="Disable CSRF token check (ONLY FOR DEVELOPMENT).")
    parser.add_argument("--disableshell", action="store_true",\
        help="Disable MORPHiS from allowing ssh shell connections from"\
            " localhost.")
    parser.add_argument("--dontuseseed", action="store_true",\
        help="Instruct the node to not attempt to connect to the official"\
            " MORPHiS seed node in the case that you have no peers.")
    parser.add_argument("--dssize", type=int,\
        help="Specify the datastore size in standard non-IEC-redefined JEDEC"\
            " MBs (default is one gigabyte, as in 1024^3 bytes). Morphis does"\
            " not deal in MiecBytes (1 MiecB = 1000^2 bytes), but in"\
            " MegaBytes (1 MB = 1024^2 bytes). Morphis does not recognize the"\
            " attempted redefinition of an existing unit by the IEC.")
    parser.add_argument("--dumptasksonexit", action="store_true",\
        help="Dump async task list on exit.")
    parser.add_argument("--enableeval", action="store_true",\
        help="Enable eval and ! commands in the shell (BAD ON SHARED HOST).")
    parser.add_argument("--instanceoffset", type=int,\
        help="Debug option to increment node instance and bind port.")
    parser.add_argument("-l", dest="logconf",\
        help="Specify alternate logging.ini [IF SPECIFIED, THIS MUST BE THE"\
            " FIRST PARAMETER!].")
    parser.add_argument("--maalstroom-bind",\
        help="Specify bind address (host:port) for Maalstroom. The default"\
            " is \":4250\"; which will listen on all interfaces on port 4251.")
    parser.add_argument("--maxconn", type=int,\
        help="Specify the maximum connections to seek.")
    parser.add_argument("--nodecount", type=int,\
        help="Specify amount of nodes to start.")
    parser.add_argument("--offline", action="store_true",\
        help="Enable offline mode. Only Maalstroom will be enabled.")
    parser.add_argument("--parallellaunch", action="store_true",\
        help="Enable parallel launch of the nodecount nodes.")
    parser.add_argument("--proxyurl",\
        help="Specify the proxy URL to rewrite URLs to for proxy requests.")
    parser.add_argument("--reinitds", action="store_true",\
        help="Allow reinitialization of the Datastore. This will only happen"\
            " if the Datastore directory has already been manually deleted.")
    parser.add_argument("--tormode", action="store_true",\
        help="Enable torify mode. This makes MORPHiS work better over torify"\
            " or proxychains. Currently it fixes the remote address check so"\
            " that more than one connection can work at a time. You still"\
            " have to wrap MORPHiS with torify or proxychains yourself.")
    parser.add_argument("--updatetest", action="store_true",\
        help="Enable update test mode; for development purposes.")
    parser.add_argument("--webdevel", action="store_true",\
        help="Enable web development mode. This causes Maalstroom to reload"\
            " the web UI modules every request.")

    args = parser.parse_args()

    addpeer = args.addpeer
    instance = args.nn
    if instance == None:
        instance = 0
    bindaddr = args.bind
    if bindaddr:
        bindaddr.split(':') # Just to preemptively test.
    else:
        bindaddr = ":4250"
    if args.cleartexttransport:
        log.info("Enabling cleartext transport.")
        mn1.enable_cleartext_transport()
    db_pool_size = args.dbpoolsize
    dburl = args.dburl
    dssize = args.dssize if args.dssize else 1024
    dumptasksonexit = args.dumptasksonexit
    instanceoffset = args.instanceoffset
    if instanceoffset:
        instance += instanceoffset
        host, port = bindaddr.split(':')
        port = int(port) + instanceoffset
        bindaddr = "{}:{}".format(host, port)
    if args.dm:
        maalstroom_enabled = False
    nodecount = args.nodecount
    if nodecount == None:
        nodecount = 1
    parallel_launch = args.parallellaunch
    reinitds = args.reinitds

    morphis_version = open("VERSION").read().strip()

    while True:
        @asyncio.coroutine
        def _start_node(instance, bindaddr):
            node = Node(loop, instance, dburl)
            node.morphis_version = morphis_version

            if args.enableeval:
                node.eval_enabled = True
            if args.disableshell:
                node.shell_enabled = False
            if args.webdevel:
                node.web_devel = True
            if args.dontuseseed:
                node.seed_node_enabled = False
            if args.tormode:
                node.tormode = True
            if args.offline:
                node.offline_mode = True

            nodes.append(node)

            if node_callback:
                node_callback(node)

            if db_pool_size:
                node.db.pool_size = db_pool_size

            if maalstroom_enabled:
                import maalstroom

                if args.maalstroom_bind:
                    maalstroom.host, mport =\
                        args.maalstroom_bind.split(':')
                    maalstroom.port = int(mport)
                if args.disable_csrf_check:
                    maalstroom.disable_csrf_check = True
                if args.dmdmail:
                    maalstroom.dmail_enabled = False
                if args.dmupload:
                    maalstroom.upload_enabled = False
                if args.proxyurl:
                    maalstroom.proxy_url = args.proxyurl

                yield from maalstroom.start_maalstroom_server(node)

            yield from node.init_db()

            if bindaddr:
                node.bind_address = bindaddr

            if parallel_launch:
                yield from loop.run_in_executor(None, node.load_key)
            else:
                node.load_key()

            node.init_chord()

            yield from\
                node.init_store(dssize << 20, reinitds) # Convert MBs to bytes.

            if args.maxconn:
                node.chord_engine.maximum_connections = args.maxconn
                node.chord_engine.hard_maximum_connections = args.maxconn * 2

            if addpeer != None:
                node.chord_engine.connect_peers = addpeer

            if maalstroom_enabled:
                import client_engine as cengine

                ce = cengine.ClientEngine(node)

                if args.updatetest:
                    ce.update_test = True
                if args.disableautopublish:
                    ce.auto_publish_enabled = False
                if args.disableautoscan:
                    ce.auto_scan_enabled = False

                maalstroom.set_client_engine(ce)

            yield from node.start()

        if parallel_launch:
            asyncio.async(_start_node(instance, bindaddr), loop=loop)
        else:
            yield from _start_node(instance, bindaddr)

        log.info("Started Instance #{}.".format(instance))

        nodecount -= 1
        if not nodecount:
            break;

        instance += 1
        host, port = bindaddr.split(':')
        port = int(port) + 1
        bindaddr = "{}:{}".format(host, port)

if __name__ == "__main__":
    main()
