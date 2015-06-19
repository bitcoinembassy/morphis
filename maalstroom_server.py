import llog

import asyncio
import cgi
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
from socketserver import ThreadingMixIn
from threading import Event

import base58
import chord
import enc
from mutil import hex_string
import rsakey
import mbase32

log = logging.getLogger(__name__)

host = "localhost"
port = 4251

node = None
server = None

upload_page_content = None
static_upload_page_content = None
static_upload_page_content_id = None

class DataResponseWrapper(object):
    def __init__(self):
        self.data = None
        self.data_key = None
        self.version = None

        self.is_done = Event()

        self.exception = None
        self.timed_out = False

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class MaalstroomHandler(BaseHTTPRequestHandler):
    def __init__(self, a, b, c):
        self.protocol_version = "HTTP/1.1"

        super().__init__(a, b, c)

    def do_GET(self):
        rpath = self.path[1:]
        if rpath[-1] == '/':
            rpath = rpath[:-1]

        s_upload = "upload"
        if rpath.startswith(s_upload):
            if rpath.startswith("upload/generate"):
                priv_key =\
                    base58.encode(\
                        rsakey.RsaKey.generate(bits=4096)._encode_key())

                self.send_response(307)
                self.send_header("Location", "{}".format(priv_key))
                self.send_header("Content-Length", 0)
                self.end_headers()
                return

            if self.headers["If-None-Match"] == static_upload_page_content_id:
                self.send_response(304)
                self.send_header("ETag", static_upload_page_content_id)
                self.send_header("Content-Length", 0)
                self.end_headers()
                return

            if len(rpath) == len(s_upload):
                content = static_upload_page_content
                content_id = static_upload_page_content_id
            else:
                content =\
                    upload_page_content.replace(\
                        b"${PRIVATE_KEY}",\
                        rpath[len(s_upload)+1:].encode())
                content =\
                    content.replace(\
                        b"${UPDATEABLE_KEY_MODE_DISPLAY}",\
                        b"")
                content =\
                    content.replace(\
                        b"${STATIC_MODE_DISPLAY}",\
                        b"display: none")

                content_id = enc.generate_ID(content)

            self.send_response(200)
            self.send_header("Content-Length", len(content))
            self.send_header("Cache-Control", "public")
            self.send_header("ETag", content_id)
            self.end_headers()
            self.wfile.write(content)
            return

        if self.headers["If-None-Match"] == rpath:
            self.send_response(304)
            self.send_header("ETag", rpath)
            self.send_header("Content-Length", 0)
            self.end_headers()
            return

        if log.isEnabledFor(logging.INFO):
            log.info("rpath=[{}].".format(rpath))

        error = False

        significant_bits = chord.NODE_ID_BITS

        lrp = len(rpath)
        try:
            if lrp == 128:
                data_key = bytes.fromhex(rpath)
            elif lrp in (103, 102):
                data_key = bytes(mbase32.decode(rpath))
#            elif lrp == 88 + 4 and rpath.startswith("get/"):
#                data_key = base58.decode(rpath[4:])
#
#                hex_key = hex_string(data_key)
#
#                message = ("<a href=\"morphis://{}\">{}</a>\n{}"\
#                    .format(hex_key, hex_key, hex_key))\
#                        .encode()
#
#                self.send_response(301)
#                self.send_header("Location", "morphis://{}".format(hex_key))
#                self.send_header("Content-Type", "text/html")
#                self.send_header("Content-Length", len(message))
#                self.end_headers()
#
#                self.wfile.write(message)
#                return
            else:
#                error = True
#                log.warning("Invalid request: [{}].".format(rpath))
                data_key = mbase32.decode(rpath, False)
                significant_bits = 5 * len(rpath)
        except:
            error = True
            log.exception("decode")

        if error:
            errmsg = b"400 Bad Request."
            self.send_response(400)
            self.send_header("Content-Length", len(errmsg))
            self.end_headers()
            self.wfile.write(errmsg)
            return

        data_rw = DataResponseWrapper()

        node.loop.call_soon_threadsafe(\
            asyncio.async, _send_get_data(data_key, significant_bits, data_rw))

        data_rw.is_done.wait()

        if significant_bits:
            if data_rw.data_key:
                key = mbase32.encode(data_rw.data_key)

                message = ("<a href=\"morphis://{}\">{}</a>\n{}"\
                    .format(key, key, key))\
                        .encode()

                self.send_response(301)
                self.send_header("Location", "morphis://{}".format(key))
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", len(message))
                self.end_headers()

                self.wfile.write(message)
                return

        if data_rw.data:
            self.send_response(200)
            if data_rw.data[0] == 0xFF and data_rw.data[1] == 0xD8:
                self.send_header("Content-Type", "image/jpg")
            elif data_rw.data[0] == 0x89 and data_rw.data[1:4] == b"PNG":
                self.send_header("Content-Type", "image/png")
            elif data_rw.data[:5] == b"GIF89":
                self.send_header("Content-Type", "image/gif")
            elif data_rw.data[:5] == b"/*CSS":
                self.send_header("Content-Type", "text/css")
            elif data_rw.data[:12] == b"/*JAVASCRIPT":
                self.send_header("Content-Type", "application/javascript")
            else:
                self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", len(data_rw.data))
            if data_rw.version:
                self.send_header("Cache-Control", "public, max-age=15")
            else:
                self.send_header("Cache-Control", "public")
                self.send_header("ETag", rpath)
            self.end_headers()

            self.wfile.write(data_rw.data)
        else:
            self.handle_error(data_rw)

    def do_POST(self):
        log.info(self.headers)

        if self.headers["Content-Type"] == "application/x-www-form-urlencoded":
            data = self.rfile.read(int(self.headers["Content-Length"]))
        else:
            form = cgi.FieldStorage(\
                fp=self.rfile,\
                headers=self.headers,\
                environ={\
                    "REQUEST_METHOD": "POST",\
                    "CONTENT_TYPE": self.headers["Content-Type"]})

            if log.isEnabledFor(logging.DEBUG):
                log.debug("form=[{}].".format(form))

            formelement = form["fileToUpload"]
            filename = formelement.filename
            data = formelement.file.read()

            if log.isEnabledFor(logging.INFO):
                log.info("filename=[{}].".format(filename))

            try:
                privatekey = form["privateKey"].value

                if privatekey == "${PRIVATE_KEY}":
                    raise KeyError()

                if log.isEnabledFor(logging.INFO):
                    log.info("privatekey=[{}].".format(privatekey))

                privatekey = base58.decode(privatekey)

                privatekey = rsakey.RsaKey(privdata=privatekey)

                path = form["path"].value
                version = form["version"].value
                if not version:
                    version = 0
                else:
                    version = int(version)
            except KeyError:
                privatekey = None

        if log.isEnabledFor(logging.DEBUG):
            log.debug("data=[{}].".format(data))

        data_rw = DataResponseWrapper()

        if privatekey:
            node.loop.call_soon_threadsafe(\
                asyncio.async, _send_store_data(\
                    data, data_rw, privatekey, path, version))
        else:
            node.loop.call_soon_threadsafe(\
                asyncio.async, _send_store_data(data, data_rw))

        data_rw.is_done.wait()

        if data_rw.data_key:
            hex_key = hex_string(data_rw.data_key)
            message = "<a href=\"morphis://{}\">perma link</a>\n{}"\
                .format(mbase32.encode(data_rw.data_key), hex_key)

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", len(message))
            self.end_headers()

            self.wfile.write(bytes(message, "UTF-8"))
        else:
            self.handle_error(data_rw)

    def handle_error(self, data_rw):
        if data_rw.exception:
            errmsg = b"500 Internal Server Error."
            self.send_response(500)
        elif data_rw.timed_out:
            errmsg = b"408 Request Timeout."
            self.send_response(408)
        else:
            errmsg = b"404 Not Found."
            self.send_response(404)

        self.send_header("Content-Length", len(errmsg))
        self.end_headers()
        self.wfile.write(errmsg)

@asyncio.coroutine
def _send_get_data(data_key, significant_bits, data_rw):
    try:
        if significant_bits < chord.NODE_ID_BITS:
            future = asyncio.async(\
                node.chord_engine.tasks.send_find_key(\
                    data_key, significant_bits),
                loop=node.loop)

            yield from asyncio.wait_for(future, 15.0, loop=node.loop)

            ct_data_rw = future.result()

            data_key = ct_data_rw.data_key

            if log.isEnabledFor(logging.INFO):
                log.info("Found key=[{}].".format(hex_string(data_key)))

            if not data_key:
                data_rw.data = b"Key Not Found"
                data_rw.version = -1
                data_rw.is_done.set()
                return

            data_rw.data_key = bytes(data_key)
            data_rw.is_done.set()
            return

        future = asyncio.async(\
            node.chord_engine.tasks.send_get_data(data_key),\
            loop=node.loop)

        yield from asyncio.wait_for(future, 15.0, loop=node.loop)

        ct_data_rw = future.result()

        data_rw.data = ct_data_rw.data
        data_rw.version = ct_data_rw.version
    except asyncio.TimeoutError:
        data_rw.timed_out = True
    except:
        log.exception("send_get_data()")
        data_rw.exception = True

    data_rw.is_done.set()

@asyncio.coroutine
def _send_store_data(data, data_rw, privatekey=None, path=None, version=None):
    try:
        def key_callback(data_key):
            data_rw.data_key = data_key

        if privatekey:
            future = asyncio.async(\
                node.chord_engine.tasks.send_store_updateable_key(\
                    data, privatekey, path, version, key_callback),\
                loop=node.loop)

            yield from asyncio.wait_for(future, 30.0, loop=node.loop)

            future = asyncio.async(\
                node.chord_engine.tasks.send_store_updateable_key_key(\
                    data, privatekey, path, key_callback),\
                loop=node.loop)

            yield from asyncio.wait_for(future, 30.0, loop=node.loop)
        else:
            future = asyncio.async(\
                node.chord_engine.tasks.send_store_data(data, key_callback),\
                loop=node.loop)

            yield from asyncio.wait_for(future, 30.0, loop=node.loop)

            future = asyncio.async(\
                node.chord_engine.tasks.send_store_key(data),\
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
    _set_upload_page(upf.read())

def _set_upload_page(content):
    global static_upload_page_content, static_upload_page_content_id,\
        upload_page_content

    static_upload_page_content =\
        content.replace(\
            b"${UPDATEABLE_KEY_MODE_DISPLAY}",\
            b"display: none")
    static_upload_page_content=\
        static_upload_page_content.replace(\
            b"${STATIC_MODE_DISPLAY}",\
            b"")

    static_upload_page_content_id =\
        hex_string(enc.generate_ID(static_upload_page_content))

    upload_page_content = content

_set_upload_page(b'<html><head><title>Morphis Maalstroom Upload</title></head><body><p>Select the file to upload below:</p><form action="upload" method="post" enctype="multipart/form-data"><input type="file" name="fileToUpload" id="fileToUpload"/><div style="${UPDATEABLE_KEY_MODE_DISPLAY}"><br/><br/><label for="privateKey">Private Key</label><textarea name="privateKey" id="privateKey" rows="5" cols="80">${PRIVATE_KEY}</textarea><br/><label for="path">Path</label><input type="textfield" name="path" id="path"/><br/><label for="version">Version</label><input type="textfield" name="version" id="version"/></div><input type="submit" value="Upload File" name="submit"/></form><p style="${STATIC_MODE_DISPLAY}"><a href="morphis://upload/generate">switch to updateable key mode</a></p></body></html>')
