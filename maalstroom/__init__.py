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

import client_engine as cengine
import enc
import mbase32
import maalstroom.templates as templates
import maalstroom.dispatcher as dispatcher
import maalstroom.dmail

log = logging.getLogger(__name__)

host = "localhost"
port = 4251

node = None
server = None
client_engine = None

upload_page_content = None
static_upload_page_content = [None, None]

update_test = False

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

#        self._inq = queue.Queue()
        self._inq = asyncio.Queue(loop=self.loop)
        self._outq = queue.Queue()

        self._dispatcher =\
            dispatcher.MaalstroomDispatcher(self, self._inq, self._outq)

        self._maalstroom_http_url_prefix = "http://{}/"
        self._maalstroom_morphis_url_prefix = "morphis://"

        super().__init__(a, b, c)

    def do_GET(self):
        self._prepare_for_request()

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Handler do_GET(): path=[{}].".format(self.path))

        self.loop.call_soon_threadsafe(\
            asyncio.async,\
            self._dispatcher.do_GET(self._get_rpath()))

        self._write_response()

    def do_POST(self):
        self._prepare_for_request()

        self.loop.call_soon_threadsafe(\
            asyncio.async,\
            self._dispatcher.do_POST(self._get_rpath()))

        log.warning("Reading request.")
        self._read_request()

        log.warning("Writing response.")
        self._write_response()

    def log_message(self, mformat, *args):
        if log.isEnabledFor(logging.INFO):
            log.info("{}: {}".format(self.address_string(), args))

    def _get_rpath(self):
        rpath = self.path[1:]

        if rpath and rpath[-1] == '/':
            rpath = rpath[:-1]

        return rpath

    def _prepare_for_request(self):
        if self.headers["X-Maalstroom-Plugin"]:
            self.maalstroom_plugin_used = True
            self.maalstroom_url_prefix_str =\
                self._maalstroom_morphis_url_prefix
            self.maalstroom_url_prefix =\
                self.maalstroom_url_prefix_str.encode()
        else:
            global port
            host = self.headers["Host"]
            if log.isEnabledFor(logging.DEBUG):
                log.debug("No plugin used for request, rewriting URLs using"\
                    " host=[{}]."\
                        .format(host))
            # Host header includes port.
            self.maalstroom_url_prefix_str =\
                self._maalstroom_http_url_prefix.format(host)
            self.maalstroom_url_prefix =\
                self.maalstroom_url_prefix_str.encode()

        if self.node.web_devel:
            importlib.reload(maalstroom.templates)
            importlib.reload(maalstroom.dispatcher)
            importlib.reload(maalstroom.dmail)

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
                break
            elif resp is Flush:
                self.wfile.flush()
                continue
            elif resp is Close:
                self.close_connection = True
                break

            self.wfile.write(resp)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class Flush(object):
    pass

class Close(object):
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

    asyncio.async(_create_client_engine(), loop=node.loop)

@asyncio.coroutine
def _create_client_engine():
    global node, client_engine, update_test
    yield from node.ready.wait()
    client_engine =\
        cengine.ClientEngine(node.chord_engine, node.loop, update_test)
    yield from client_engine.start()

def shutdown():
    if not server:
        return

    log.info("Shutting down Maalstroom server instance.")
    server.server_close()
    log.info("Maalstroom server instance stopped.")

def set_upload_page(filepath):
    global upload_page_content

    with open(filepath, "rb") as upf:
        _set_upload_page(upf.read())

def _set_upload_page(content):
    global static_upload_page_content, upload_page_content

    upload_page_content = content

    content = content.replace(\
        b"${UPDATEABLE_KEY_MODE_DISPLAY}",\
        b"display: none")
    content = content.replace(\
        b"${STATIC_MODE_DISPLAY}",\
        b"")

    static_upload_page_content[0] = content
    static_upload_page_content[1] =\
        mbase32.encode(enc.generate_ID(static_upload_page_content[0]))

_set_upload_page(b'<html><head><title>MORPHiS Maalstroom Upload</title></head><body><h4 style="${UPDATEABLE_KEY_MODE_DISPLAY}">NOTE: Bookmark this page to save your private key in the bookmark!</h4>Select the file to upload below:</p><form action="upload" method="post" enctype="multipart/form-data"><input type="file" name="fileToUpload" id="fileToUpload"/><div style="${UPDATEABLE_KEY_MODE_DISPLAY}"><br/><br/><label for="privateKey">Private Key</label><textarea name="privateKey" id="privateKey" rows="5" cols="80">${PRIVATE_KEY}</textarea><br/><label for="path">Path</label><input type="textfield" name="path" id="path"/><br/><label for="version">Version</label><input type="textfield" name="version" id="version" value="${VERSION}"/><br/><label for="mime_type">Mime Type</label><input type="textfield" name="mime_type" id="mime_type"/><br/></div><input type="submit" value="Upload File" name="submit"/></form><p style="${STATIC_MODE_DISPLAY}"><a href="morphis://.upload/generate">switch to updateable key mode</a></p><p style="${UPDATEABLE_KEY_MODE_DISPLAY}"><a href="morphis://.upload/">switch to static key mode</a></p><h5><- <a href="morphis://">MORPHiS UI</a></h5></body></html>')
