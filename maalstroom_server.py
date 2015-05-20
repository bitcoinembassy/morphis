import llog

import asyncio
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
from socketserver import ThreadingMixIn
from threading import Event

log = logging.getLogger(__name__)

host = "localhost"
port = 4251

node = None
server = None

class DataResponseWrapper(object):
    def __init__(self):
        self.data = None

        self.is_done = Event()

        self.exception = None
        self.timed_out = False

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass

class MaalstroomHandler(BaseHTTPRequestHandler):
    def __init__(self, a, b, c):
        super().__init__(a, b, c)

        self.protocol_version = "HTTP/1.1"

    def do_GET(self):
        try:
            data_key_hex = self.path[1:]
            if data_key_hex[-1] == '/':
                data_key_hex = data_key_hex[:-1]

            if log.isEnabledFor(logging.INFO):
                log.info("data_key_hex=[{}].".format(data_key_hex))

            if self.headers["If-None-Match"] == data_key_hex:
                self.send_response(304)
                self.send_header("ETag", data_key_hex)
                self.end_headers()
                return

            data_key = bytes.fromhex(data_key_hex)
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
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", len(data_rw.data))
            self.send_header("Cache-Control", "public")
            self.send_header("ETag", data_key_hex)
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

        yield from asyncio.wait_for(future, 1.0, loop=node.loop)

        data_rw.data = future.result()
    except asyncio.TimeoutError:
        data_rw.timed_out = True
    except:
        log.exception("send_get_data()")
        data_rw.exception = True

    data_rw.is_done.set()

@asyncio.coroutine
def init_maalstroom_server(the_node):
    global node, server

    if node:
        #TODO: Handle this better, but for now this is how we only start one
        # maalstroom process even when running in multi-instance test mode.
        return

    node = the_node

    log.info("Starting Maalstroom server instance.")

    server = ThreadedHTTPServer((host, port), MaalstroomHandler)

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
