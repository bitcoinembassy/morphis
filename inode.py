# Höfundarréttur (c) eilífur  Heimur-Heilinn
# License: GPL v2.

import llog

import asyncio
import logging
import threading

import db
import dds
import dmail
import mbase32
import mutil
import node as morphis_node
import sshtype
import synapse as syn
import targetedblock as tb

log = logging.getLogger(__name__)

node = None
loop = None

def main():
    global loop, node
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def node_callback(val):
        global node
        assert node is None
        node = val

    morphis_node.node_callback = node_callback
    morphis_node.main()

    node = morphis_node.nodes[0]
    print("NODE=[{}].".format(node))

if __name__ == "__main__":
    threading.Thread(target=main, name="MORPHiS Node", daemon=True).start()

def yf(coroutine):
    return mutil.yield_from_thread_safe(loop, coroutine)

## Example usage:
# To print out contents of [ire6bomibt4q9zp5bpd9wa7wzusxab8h]:
# python3 -i inode.py -l logging-ms.ini --webdevel
# yf(node.engine.tasks.send_get_data(bytes(mbase32.decode("ire6bomibt4q9zp5bpd9wa7wzusxab8hb4z1bspw35sdtp8977t58wa3dtprk985swgbtf7nkbkdc65o5ehzmsbqkfxwattxfztgsk1")))).data

