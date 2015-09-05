# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
import functools
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib
import logging
import queue
from socketserver import ThreadingMixIn
import threading

import client_engine as cengine
import enc
import mbase32
import maalstroom.templates as templates
import maalstroom.dispatcher as dispatcher
import maalstroom.dmail

log = logging.getLogger(__name__)

host = ""
port = 4251

node = None
server = None
client_engine = None

dmail_enabled = True
upload_enabled = True

proxy_url = None

_request_lock = threading.Lock()
_concurrent_request_count = 0

req_dict = []

class MaalstroomHandler(BaseHTTPRequestHandler):
    def __init__(self, a, b, c):
        global node
        self.loop = node.loop
        self.protocol_version = "HTTP/1.1"
        self.node = node

        self.maalstroom_plugin_used = False
        self.maalstroom_url_prefix = None
        self.maalstroom_url_prefix_str = None
        self.actual_url_prefix_str = None

        self.proxy_used = False

#        self._inq = queue.Queue()
        self._inq = asyncio.Queue(loop=self.loop)
        self._outq = queue.Queue()

        self._abort_event = threading.Event()

        self._dispatcher = self._create_dispatcher()

        self._maalstroom_http_url_prefix = "http://{}/"
        self._maalstroom_morphis_url_prefix = "morphis://"

        super().__init__(a, b, c)

    def do_GET(self):
        self._prepare_for_request()

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Handler do_GET(): path=[{}].".format(self.path))
            req_dict.append(self)

        self.loop.call_soon_threadsafe(\
            asyncio.async,\
            self._dispatcher.do_GET(self._get_rpath()))

        self._write_response()

        if self.node.web_devel and self.headers["Cache-Control"] == "no-cache":
            global _concurrent_request_count
            with _request_lock:
                _concurrent_request_count -= 1

        if log.isEnabledFor(logging.DEBUG):
            req_dict.remove(self)
            log.debug("Done do_GET(): path=[{}], reqs=[{}]."\
                .format(self.path, len(req_dict)))

    def do_POST(self):
        self._prepare_for_request()

        self.loop.call_soon_threadsafe(\
            asyncio.async,\
            self._dispatcher.do_POST(self._get_rpath()))

        log.debug("Reading request.")
        self._read_request()

        log.debug("Writing response.")
        self._write_response()

        if self.node.web_devel and self.headers["Cache-Control"] == "no-cache":
            global _concurrent_request_count
            with _request_lock:
                _concurrent_request_count -= 1

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Done do_POST(): path=[{}].".format(self.path))

    def log_message(self, mformat, *args):
        if log.isEnabledFor(logging.INFO):
            log.info("{}: {}".format(self.address_string(), args))

    def _create_dispatcher(self):
        return dispatcher.MaalstroomDispatcher(\
            self, self._inq, self._outq, self._abort_event)

    def _prepare_for_request(self):
        self._abort_event.clear()

        global proxy_url

        if self.headers["X-Forwarded-For"]:
            self.proxy_used = True

        if self.headers["X-Maalstroom-Plugin"]:
            self.maalstroom_plugin_used = True
            self.maalstroom_url_prefix_str =\
                self._maalstroom_morphis_url_prefix
            self.maalstroom_url_prefix =\
                self.maalstroom_url_prefix_str.encode()

            if self.proxy_used and proxy_url:
                self.actual_url_prefix_str = proxy_url
            else:
                self.actual_url_prefix_str =\
                    self._maalstroom_http_url_prefix.format(\
                        self.headers["Host"])
        else:
            global port

            if self.proxy_used and proxy_url:
                # Host header includes port.
                self.maalstroom_url_prefix_str = proxy_url
            else:
                host = self.headers["Host"]
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(\
                        "No plugin used for request, rewriting URLs using"\
                            " host=[{}]."\
                                .format(host))
                # Host header includes port.
                self.maalstroom_url_prefix_str =\
                    self._maalstroom_http_url_prefix.format(host)

            self.maalstroom_url_prefix =\
                self.maalstroom_url_prefix_str.encode()

        if self.node.web_devel and self.headers["Cache-Control"] == "no-cache":
            global _concurrent_request_count
            with _request_lock:
                _concurrent_request_count += 1
                if _concurrent_request_count == 1:
                    log.warning(\
                        "Reloading maalstroom packages due to web_dev mode.")
                    try:
                        importlib.reload(maalstroom.templates)
                        importlib.reload(maalstroom.dispatcher)
                        importlib.reload(maalstroom.dmail)
                    except KeyboardInterrupt:
                        raise
                    except Exception as e:
                        log.exception(e)

            self._dispatcher = self._create_dispatcher()

    def _get_rpath(self):
        rpath = self.path[1:]

        if self.maalstroom_plugin_used and len(rpath) == 1 and rpath[0] == '/':
            rpath = ""

        return rpath

    def _read_request(self):
        inq = self._inq
        loop = self.loop

        rlen = int(self.headers["Content-Length"])

        while rlen:
            data = self.rfile.read(min(rlen, 65536))
            self.loop.call_soon_threadsafe(\
                functools.partial(\
                    asyncio.async,\
                    inq.put(data),\
                    loop=self.loop))
            rlen -= len(data)

        self.loop.call_soon_threadsafe(\
            functools.partial(\
                asyncio.async,\
                inq.put(None),\
                loop=self.loop))

    def _write_response(self):
        outq = self._outq

        while True:
            resp = outq.get()

            if not resp:
                # Python bug as far as I can tell. Randomly outq has a None
                # in it in front of what we really added. What we really added
                # is still there, just has a spurious None in front; so we
                # ignore it.
                log.debug("Got spurious None from queue; ignoring.")
                continue
            elif resp is Done:
                log.debug("Got Done from queue; finished.")
                break
            elif resp is Flush:
                self.wfile.flush()
                continue
            elif resp is Close:
                log.debug("Got Close from queue; closing connection.")
                self.close_connection = True
                break

            try:
                self.wfile.write(resp)
            except ConnectionError as e:
                log.warning("Browser broke connection: {}".format(e))
                self._abort_event.set()
                # Replace _outq, as dispatcher may still write to it.
                self._outq = queue.Queue()
                break

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class Flush(object):
    pass

class Close(object):
    pass

class Done(object):
    pass

@asyncio.coroutine
def start_maalstroom_server(the_node):
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

def set_client_engine(ce):
    global _client_engine

    _client_engine = ce

@asyncio.coroutine
def get_client_engine():
    global node, client_engine, _client_engine

    if client_engine:
        return client_engine

    yield from node.ready.wait()

    yield from _client_engine.start()

    client_engine = _client_engine

    return client_engine

def shutdown():
    if not server:
        return

    log.info("Shutting down Maalstroom server instance.")
    server.server_close()
    log.info("Maalstroom server instance stopped.")
