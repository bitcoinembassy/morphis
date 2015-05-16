import llog

import asyncio
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
from threading import Event

log = logging.getLogger(__name__)

host = "localhost"
port = 5555

node = None
server = None

class DataResponseWrapper(object):
    def __init__(self):
        self.data = None

        self.is_done = Event()

        self.exception = None
        self.timed_out = False

class MaalstroomHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        data_key = self.path[1:]

        if log.isEnabledFor(logging.INFO):
            log.info("data_key=[{}].".format(data_key))

        try:
            data_key = bytes.fromhex(data_key)
        except:
            log.exception("fromhex(..)")

            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"400 Bad Request.")
            return

        data_rw = DataResponseWrapper()

        node.loop.call_soon_threadsafe(\
            asyncio.async, _send_get_data(data_key, data_rw))

        data_rw.is_done.wait()

        if data_rw.data:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            self.wfile.write(data_rw.data)
        else:
            if data_rw.exception:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"500 Internal Server Error.")
            elif data_rw.timed_out:
                self.send_response(408)
                self.end_headers()
                self.wfile.write(b"408 Request Timeout.")
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"404 Not Found.")

@asyncio.coroutine
def _send_get_data(data_key, data_rw):
    try:
        future = asyncio.async(\
            node.chord_engine.tasks.send_get_data(data_key),\
            loop=node.loop)

        try:
            yield from asyncio.wait_for(future, 1.0, loop=node.loop)
        except asyncio.TimeoutError:
            data_rw.timed_out = True
            return

        data_rw.data = future.result()
    except:
        log.exception("send_get_data()")

        data_rw.exception = True

    data_rw.is_done.set()

@asyncio.coroutine
def init_maalstroom_server(the_node):
    global node, server

    if node:
        #FIXME: Handle this better, but for now this is how we only start one
        # maalstroom process even when running in multi-instance test mode.
        return

    log.info("Starting Maalstroom server instance.")

    node = the_node

    server = HTTPServer((host, port), MaalstroomHandler)

    def threadcall():
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass

        server.server_close()

    node.loop.run_in_executor(None, threadcall)

def shutdown():
    if not server:
        return

    log.info("Shutting down Maalstroom server instance.")
    server.server_close()
    log.info("Mallstroom server instance stopped.")
