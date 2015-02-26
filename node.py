import llog

import asyncio
import logging
import os
import argparse

import packet as mnetpacket
import rsakey
import mn1
from mutil import hex_dump
import chord
import peer

log = logging.getLogger(__name__)

class Node():
    def __init__(self, loop):
        self.loop = loop
        self.node_key = None
        self.chord_engine = None
        self.instance = None
        self.bind_address = None

    def get_loop(self):
        return self.loop

    def get_node_key(self):
        return self.node_key

    def set_bind_address(self, value):
        self.bind_address = value

    def start(self):
        if not self.node_key:
            self._load_key()

        self.chord_engine = chord.ChordEngine(self, self.bind_address)
        self.chord_engine.start()

    def stop(self):
        self.chord_engine.stop()

    def _load_key(self):
        if self.instance:
            key_filename = "node_key-rsa-{}.mnk".format(self.instance)
        else:
            key_filename = "node_key-rsa.mnk"

        if os.path.exists(key_filename):
            log.info("Node private key file found, loading.")
            self.node_key = rsakey.RsaKey(filename=key_filename)
        else:
            log.info("Node private key file missing, generating.")
            self.node_key = rsakey.RsaKey.generate(bits=4096)
            self.node_key.write_private_key_file(key_filename)

def main():
    print("Launching node.")
    log.info("Launching node.")

    parser = argparse.ArgumentParser()
    parser.add_argument("--nn", help="Node instance number.")
    parser.add_argument("--addnode", help="Add a node to peer list.", action="append")
    parser.add_argument("--bind", help="Specify bind address (host:port).")
    parser.add_argument("--nodecount", type=int, help="Specify amount of nodes to start.")
    args = parser.parse_args()

    addnode = args.addnode
    instance = args.nn
    if instance == None:
        instance = 0
    bindaddr = args.bind
    if bindaddr == None:
        bindaddr = "127.0.0.1:5555"
    nodecount = args.nodecount
    if nodecount == None:
        nodecount = 1

    loop = asyncio.get_event_loop()

    nodes = []

    while True:
        node = Node(loop)
        nodes.append(node)

        if instance:
            node.instance = instance
        if bindaddr:
            bindaddr.split(':') # Just to preemptively test.
            node.set_bind_address(bindaddr)

        node.start()

        if addnode != None:
            for addnodei in addnode:
                host, port = addnodei.split(':')
                node.chord_engine.add_peer(host, port)

        nodecount -= 1
        if not nodecount:
            break;

        instance += 1
        host, port = bindaddr.split(':')
        port = int(port) + 1
        bindaddr = "{}:{}".format(host, port)

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

if __name__ == "__main__":
    main()
