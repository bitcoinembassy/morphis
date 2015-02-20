import llog

import asyncio
import logging
import os

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

        self._load_key()

    def get_loop(self):
        return self.loop

    def get_node_key(self):
        return self.node_key

    def start(self):
        self.chord_engine = chord.ChordEngine(self)
        self.chord_engine.start()

    def stop(self):
        self.chord_engine.stop()

    def _load_key(self):
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

    loop = asyncio.get_event_loop()

    node = Node(loop)
    node.start()

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        log.info("Got KeyboardInterrupt; shutting down.")
    except:
        log.exception("loop.run_forever() threw:")

    node.stop()
    loop.close()

    log.info("Shutdown.")

if __name__ == "__main__":
    main()
