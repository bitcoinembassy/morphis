# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
import logging
import os
import argparse

from sqlalchemy import update, func

import packet as mnetpacket
import rsakey
import maalstroom_server as maalstroom
import mn1
from mutil import hex_dump, hex_string
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

dumptasksonexit = False
maalstroom_enabled = False

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

    @property
    def all_nodes(self):
        global nodes
        return nodes

    def init_db(self):
        if self._db_initialized:
            log.debug("The database is already initialized.")
            return

        if not os.path.exists("data"):
            log.info("The 'data' directory was missing; creating.")
            os.makedirs("data")

        self.db.init_engine()
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
                with self.db.open_session() as sess:
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
                            .format(hex_string(max_distance)))

                    return datastore_size, max_distance

            self.datastore_size, self.chord_engine.furthest_data_block =\
                yield from self.loop.run_in_executor(None, dbcall)

        assert type(self.chord_engine.furthest_data_block) is bytes

    @asyncio.coroutine
    def create_schema(self):
        yield from self.db.create_all()

    @asyncio.coroutine
    def start(self):
        if not self._db_initialized:
            self.init_db()

        def dbcall():
            log.info("Clearing out connected state from Peer table.")
            with self.db.open_session() as sess:
                sess.execute(update(db.Peer, bind=self.db.engine)\
                    .values(connected=False, last_connect_attempt=None))
                sess.commit()

        yield from self.loop.run_in_executor(None, dbcall)

        self.chord_engine.bind_address = self.bind_address

        yield from self.chord_engine.start()

    def stop(self):
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

    #loop.run_until_complete(_main(loop))
    asyncio.async(_main(), loop=loop)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        log.info("Got KeyboardInterrupt; shutting down.")
        if dumptasksonexit or log.isEnabledFor(logging.DEBUG):
            try:
                for task in asyncio.Task.all_tasks(loop=loop):
                    print("Task [{}]:".format(task))
                    task.print_stack()
            except:
                log.exception("Task")
    except:
        log.exception("loop.run_forever() threw:")

    for node in nodes:
        node.stop()
    loop.close()

    if maalstroom_enabled:
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
        help="Specify bind address (host:port).")
    parser.add_argument("--cleartexttransport", action="store_true",\
        help="Clear text transport and no authentication.")
    parser.add_argument("--dbpoolsize", type=int,\
        help="Specify the maximum amount of database connections.")
    parser.add_argument("--dburl",\
        help="Specify the database url to use.")
    parser.add_argument("--dm", action="store_true",\
        help="Disable Maalstroom server.")
    parser.add_argument("--dssize", type=int,\
        help="Specify the datastore size in standard non-IEC-redefined JEDEC"\
            " MBs (default is one gigabyte, as in 1024^3 bytes). Morphis does"\
            " not deal in MiecBytes (1 MiecB = 1000^2 bytes), but in"\
            " MegaBytes (1 MB = 1024^2 bytes). Morphis does not recognize the"\
            " attempted redefinition of an existing unit by the IEC.")
    parser.add_argument("--dumptasksonexit", action="store_true",\
        help="Dump async task list on exit.")
    parser.add_argument("--instanceoffset", type=int,\
        help="Debug option to increment node instance and bind port.")
    parser.add_argument("-l", dest="logconf",\
        help="Specify alternate logging.ini [IF SPECIFIED, THIS MUST BE THE"\
            " FIRST PARAMETER!].")
    parser.add_argument("--maxconn", type=int,\
        help="Specify the maximum connections to seek.")
    parser.add_argument("--maaluppage",\
        help="Override Maalstroom upload page with the specified file.")
    parser.add_argument("--nodecount", type=int,\
        help="Specify amount of nodes to start.")
    parser.add_argument("--parallellaunch", action="store_true",\
        help="Enable parallel launch of the nodecount nodes.")
    parser.add_argument("--reinitds", action="store_true",\
        help="Allow reinitialization of the Datastore. This will only happen"\
            " if the Datastore directory has already been manually deleted.")

    args = parser.parse_args()

    addpeer = args.addpeer
    instance = args.nn
    if instance == None:
        instance = 0
    bindaddr = args.bind
    if bindaddr:
        bindaddr.split(':') # Just to preemptively test.
    else:
        bindaddr = "127.0.0.1:4250"
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
    maalstroom_enabled = False if args.dm else True
    maaluppage = args.maaluppage
    nodecount = args.nodecount
    if nodecount == None:
        nodecount = 1
    parallel_launch = args.parallellaunch
    reinitds = args.reinitds

    while True:
        @asyncio.coroutine
        def _start_node(instance, bindaddr):
            node = Node(loop, instance, dburl)
            nodes.append(node)

            if db_pool_size:
                node.db.pool_size = db_pool_size

            if maalstroom_enabled:
                if maaluppage:
                    maalstroom.set_upload_page(maaluppage)
                yield from maalstroom.start_maalstroom_server(node)

            node.init_db()
            yield from node.create_schema()

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
