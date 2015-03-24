import llog

import asyncio
import logging
import os
import argparse

from sqlalchemy import update

import packet as mnetpacket
import rsakey
import mn1
from mutil import hex_dump
import chord
import peer
import db

log = logging.getLogger(__name__)

loop = None
nodes = []

dumptasksonexit = False

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

        if dburl:
            self.db = db.Db(loop, dburl, 'n' + str(instance_id))
        else:
            dburl = "sqlite:///morphis{}.sqlite".format(self.instance_postfix)
            self.db = db.Db(loop, dburl)

        self.bind_address = None
        self.unsecured_transport = None

    @property
    def all_nodes(self):
        global nodes
        return nodes

    @asyncio.coroutine
    def create_schema(self):
        yield from self.db.create_all()

    @asyncio.coroutine
    def start(self):
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
        key_filename = "node_key-rsa{}.mnk".format(self.instance_postfix)

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

    log.info("Shutdown.")

@asyncio.coroutine
def _main():
    global loop

    try:
        yield from __main()
    except SystemExit:
        loop.stop()

@asyncio.coroutine
def __main():
    global loop, nodes, dumptasksonexit

    print("Launching node.")
    log.info("Launching node.")

    parser = argparse.ArgumentParser()
    parser.add_argument("--nn", type=int,\
        help="Node instance number.")
    parser.add_argument("--addpeer",\
        help="Add a node to peer list.", action="append")
    parser.add_argument("--bind",\
        help="Specify bind address (host:port).")
    parser.add_argument("--nodecount", type=int,\
        help="Specify amount of nodes to start.")
    parser.add_argument("--parallellaunch", action="store_true",\
        help="Enable parallel launch of the nodecount nodes.")
    parser.add_argument("--cleartexttransport", action="store_true",\
        help="Clear text transport and no authentication.")
    parser.add_argument("--dburl",\
        help="Specify the database url to use.")
    parser.add_argument("--dumptasksonexit", action="store_true",\
        help="Dump async task list on exit.")
    parser.add_argument("--instanceoffset", type=int,\
        help="Debug option to increment node instance and bind port.")
    parser.add_argument("-l", dest="logconf",\
        help="Specify alternate logging.ini [IF SPECIFIED, THIS MUST BE THE"\
            " FIRST PARAMETER!].")
    args = parser.parse_args()

    addpeer = args.addpeer
    instance = args.nn
    if instance == None:
        instance = 0
    bindaddr = args.bind
    if bindaddr:
        bindaddr.split(':') # Just to preemptively test.
    else:
        bindaddr = "127.0.0.1:5555"
    instanceoffset = args.instanceoffset
    if instanceoffset:
        instance += instanceoffset
        host, port = bindaddr.split(':')
        port = int(port) + instanceoffset
        bindaddr = "{}:{}".format(host, port)
    nodecount = args.nodecount
    if nodecount == None:
        nodecount = 1
    parallel_launch = args.parallellaunch
    if args.cleartexttransport:
        log.info("Enabling cleartext transport.")
        mn1.enable_cleartext_transport()
    dburl = args.dburl
    dumptasksonexit = args.dumptasksonexit

    while True:

        @asyncio.coroutine
        def _start_node(instance, bindaddr):
            node = Node(loop, instance, dburl)
            nodes.append(node)

            yield from node.create_schema()

            if bindaddr:
                node.bind_address = bindaddr

            if parallel_launch:
                yield from loop.run_in_executor(None, node.load_key)
            else:
                node.load_key()

            node.init_chord()
            yield from node.start()

            if addpeer != None:
                for peer in addpeer:
                    for peer in addpeer:
                        yield from node.chord_engine.connect_peer(peer)

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
