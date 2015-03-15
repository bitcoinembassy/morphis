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

class Node():
    def __init__(self, loop, instance_id=None, dburl=None):
        self.loop = loop

        self.instance = instance_id
        if instance_id:
            self.instance_postfix = "-{}".format(instance_id)
        else:
            self.instance_postfix = ""

        self.node_key = self._load_key()

        if dburl:
            self.db = db.Db(dburl, 'n' + str(instance_id))
        else:
            dburl = "sqlite:///morphis{}.sqlite".format(self.instance_postfix)
            self.db = db.Db(dburl)

        self.bind_address = None
        self.unsecured_transport = None

        self.chord_engine = chord.ChordEngine(self)

    def get_loop(self):
        return self.loop

    def get_db(self):
        return self.db

    def get_node_key(self):
        return self.node_key

    def set_bind_address(self, value):
        self.bind_address = value

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

def main():
    global loop, nodes

    loop = asyncio.get_event_loop()

    #loop.run_until_complete(_main(loop))
    asyncio.async(_main(), loop=loop)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        log.info("Got KeyboardInterrupt; shutting down.")
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
    global loop, nodes

    print("Launching node.")
    log.info("Launching node.")

    parser = argparse.ArgumentParser()
    parser.add_argument("--nn", type=int, help="Node instance number.")
    parser.add_argument("--addpeer", help="Add a node to peer list.", action="append")
    parser.add_argument("--bind", help="Specify bind address (host:port).")
    parser.add_argument("--nodecount", type=int, help="Specify amount of nodes to start.")
    parser.add_argument("--cleartexttransport", type=bool, help="Clear text transport and no authentication.")
    parser.add_argument("--dburl", help="Specify the database url to use.")
    args = parser.parse_args()

    addpeer = args.addpeer
    instance = args.nn
    if instance == None:
        instance = 0
    bindaddr = args.bind
    if bindaddr == None:
        bindaddr = "127.0.0.1:5555"
    nodecount = args.nodecount
    if nodecount == None:
        nodecount = 1
    if args.cleartexttransport:
        log.info("Enabling cleartext transport.")
        mn1.enable_cleartext_transport()
    dburl = args.dburl

    nodes = []

    while True:
        node = Node(loop, instance, dburl)
        nodes.append(node)

        if bindaddr:
            bindaddr.split(':') # Just to preemptively test.
            node.set_bind_address(bindaddr)
        if addpeer != None:
            for peer in addpeer:
                yield from node.chord_engine.add_peer(peer)

        yield from node.start()

        nodecount -= 1
        if not nodecount:
            break;

        instance += 1
        host, port = bindaddr.split(':')
        port = int(port) + 1
        bindaddr = "{}:{}".format(host, port)

if __name__ == "__main__":
    main()
