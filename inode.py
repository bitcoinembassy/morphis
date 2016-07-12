# Höfundarréttur (c) eilífur  Heimur-Heilinn
# License: GPL v2.

import asyncio
import threading
import queue

import db
import dds
import dmail
import mbase32
import mutil
import node as morphis_node
import sshtype
import synapse as syn
import targetedblock as tb

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

@asyncio.coroutine
def _yield_from(coroutine, result_queue):
    r = yield from coroutine
    result_queue.put(r)

def _schedule_yield_from(coroutine, result_queue):
    task = asyncio.async(_yield_from(coroutine, result_queue))

def yf(coroutine):
    result_queue = queue.Queue()
    loop.call_soon_threadsafe(_schedule_yield_from, coroutine, result_queue)
    return result_queue.get()

## Example usage:
# To print out contents of [samzu1ctt7kscitkrt5jft91gtw5c1i6]:
# python3 -i inode.py -l logging-ms.ini --webdevel
# yf(node.engine.tasks.send_get_data(bytes(mbase32.decode("samzu1ctt7kscitkrt5jft91gtw5c1i6aiujd6g5qrm13w3peph4kjusp737q5zr1cijr9rwmrcw3sgxf8143kw69zph55s71hcicqa")))).data

