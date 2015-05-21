import llog

import asyncio
import cgi
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
from socketserver import ThreadingMixIn
from threading import Event

import enc
from mutil import hex_string

log = logging.getLogger(__name__)

host = "localhost"
port = 4251

node = None
server = None

upload_page_content = b'<html><head><title>Morphis Maalstroom Upload</title></head><body><p>Select the file to upload below:</p><form action="upload" method="post" enctype="multipart/form-data"><input type="file" name="fileToUpload" id="fileToUpload"/><input type="submit" value="Upload File" name="submit"/></form></body></html>'
upload_page_content_id = hex_string(enc.generate_ID(upload_page_content))

class DataResponseWrapper(object):
    def __init__(self):
        self.data = None
        self.data_key = None

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

            if data_key_hex == "upload":
                if self.headers["If-None-Match"] == upload_page_content_id:
                    self.send_response(304)
                    self.send_header("ETag", upload_page_content_id)
                    self.end_headers()
                    return

                self.send_response(200)
                self.send_header("Content-Length", len(upload_page_content))
                self.send_header("Cache-Control", "public")
                self.send_header("ETag", upload_page_content_id)
                self.end_headers()
                self.wfile.write(upload_page_content)
                return

            if self.headers["If-None-Match"] == data_key_hex:
                self.send_response(304)
                self.send_header("ETag", data_key_hex)
                self.end_headers()
                return

            if log.isEnabledFor(logging.INFO):
                log.info("data_key_hex=[{}].".format(data_key_hex))

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
            if data_rw.data[0] == 0xFF and data_rw.data[1] == 0xD8:
                self.send_header("Content-Type", "image/jpg")
            else:
                self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", len(data_rw.data))
            self.send_header("Cache-Control", "public")
            self.send_header("ETag", data_key_hex)
            self.end_headers()

            self.wfile.write(data_rw.data)
        else:
            self.handle_error(data_rw)

    def do_POST(self):
        log.info(self.headers)
        form = cgi.FieldStorage(\
            fp=self.rfile,\
            headers=self.headers,\
            environ={\
                "REQUEST_METHOD": "POST",\
                "CONTENT_TYPE": self.headers["Content-Type"]})

        log.info("form=[{}].".format(form))

        formelement = form["fileToUpload"]
        filename = formelement.filename
        data = formelement.file.read()
        log.info("filename=[{}].".format(filename))
        log.info("data=[{}].".format(data))

        data_rw = DataResponseWrapper()

        node.loop.call_soon_threadsafe(\
            asyncio.async, _send_store_data(data, data_rw))

        data_rw.is_done.wait()

        if data_rw.data_key:
            message = hex_string(data_rw.data_key)

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", len(message))
            self.end_headers()

            self.wfile.write(bytes(message, "UTF-8"))
        else:
            self.handle_error(data_rw)

    def handle_error(self, data_rw):
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

        yield from asyncio.wait_for(future, 5.0, loop=node.loop)

        data_rw.data = future.result()
    except asyncio.TimeoutError:
        data_rw.timed_out = True
    except:
        log.exception("send_get_data()")
        data_rw.exception = True

    data_rw.is_done.set()

@asyncio.coroutine
def _send_store_data(data, data_rw):
    try:
        def key_callback(data_key):
            data_rw.data_key = data_key

        future = asyncio.async(\
            node.chord_engine.tasks.send_store_data(data, key_callback),\
            loop=node.loop)

        yield from asyncio.wait_for(future, 30.0, loop=node.loop)
    except asyncio.TimeoutError:
        data_rw.timed_out = True
    except:
        log.exception("send_store_data()")
        data_rw.exception = True

    data_rw.is_done.set()

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

def shutdown():
    if not server:
        return

    log.info("Shutting down Maalstroom server instance.")
    server.server_close()
    log.info("Mallstroom server instance stopped.")

def set_upload_page(filepath):
    global upload_page_content

    upf = open(filepath, "rb")
    upload_page_content = upf.read()
    upload_page_content_id = enc.generate_ID(upload_page_content)
