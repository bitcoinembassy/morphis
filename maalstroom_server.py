import llog

import asyncio
import cgi
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import queue
from socketserver import ThreadingMixIn
from threading import Event

import base58
import chord
import enc
from mutil import hex_string, decode_key
import rsakey
import mbase32
import multipart

log = logging.getLogger(__name__)

host = "localhost"
port = 4251

node = None
server = None

home_page_content = [b'<html><head><title>Morphis</title></head><body><a href="morphis://3syweaeb7xwm4q3hxfp9w4nynhcnuob6r1mhj19ntu4gikjr7nhypezti4t1kacp4eyy3hcbxdbm4ria5bayb4rrfsafkscbik7c5ue/">Morphis Homepage</a><br/><br/><a href="morphis://upload">Upload</a><br/></body></html>', None]

upload_page_content = None
static_upload_page_content = [None, None]

class DataResponseWrapper(object):
    def __init__(self):
        self.data = None
        self.size = None
        self.data_key = None
        self.version = None

        self.is_done = Event()
        self.data_queue = queue.Queue()

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

        if rpath and rpath[-1] == '/':
            rpath = rpath[:-1]

        if not rpath:
            self._send_content(home_page_content)
            return

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

            if len(rpath) == len(s_upload):
                self._send_content(static_upload_page_content)
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

                content_id = mbase32.encode(enc.generate_ID(content))

                self._send_content((content, content_id))

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

        significant_bits = None

        try:
            data_key, significant_bits = decode_key(rpath)
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
            asyncio.async,\
            _send_get_data(data_key, significant_bits, data_rw))

        data = data_rw.data_queue.get()

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

        if data:
            self.send_response(200)
            if data[0] == 0xFF and data[1] == 0xD8:
                self.send_header("Content-Type", "image/jpg")
            elif data[0] == 0x89 and data[1:4] == b"PNG":
                self.send_header("Content-Type", "image/png")
            elif data[:5] == b"GIF89":
                self.send_header("Content-Type", "image/gif")
            elif data[:5] == b"/*CSS":
                self.send_header("Content-Type", "text/css")
            elif data[:12] == b"/*JAVASCRIPT":
                self.send_header("Content-Type", "application/javascript")
            elif data[:8] == bytes(\
                    [0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70]):
                self.send_header("Content-Type", "video/mp4")
            else:
                self.send_header("Content-Type", "text/html")

            self.send_header("Content-Length", data_rw.size)

            if data_rw.version is not None:
                self.send_header("Cache-Control", "max-age=15, public")
            else:
                self.send_header("Cache-Control", "public")
                self.send_header("ETag", rpath)
            self.end_headers()

            while True:
                self.wfile.write(data)

                data = data_rw.data_queue.get()

                if data is None:
                    break
        else:
            self._handle_error(data_rw)

    def do_POST(self):
        log.info(self.headers)

        if self.headers["Content-Type"] == "application/x-www-form-urlencoded":
            data = self.rfile.read(int(self.headers["Content-Length"]))
            privatekey = None
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

                path = form["path"].value.encode()
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
            self._handle_error(data_rw)

    def _send_content(self, content_entry):
        content = content_entry[0]
        content_id = content_entry[1]

        if not content_id:
            if callable(content):
                content = content()

            content_id = mbase32.encode(enc.generate_ID(content))
            content_entry[1] = content_id

        if self.headers["If-None-Match"] == content_id:
            self.send_response(304)
            self.send_header("ETag", content_id)
            self.send_header("Content-Length", 0)
            self.end_headers()
            return

        if callable(content):
            content = content()

        self.send_response(200)
        self.send_header("Content-Length", len(content))
        self.send_header("Cache-Control", "public")
        self.send_header("ETag", content_id)
        self.end_headers()
        self.wfile.write(content)
        return

    def _handle_error(self, data_rw):
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

class Downloader(multipart.DataCallback):
    def __init__(self, data_rw):
        super().__init__()

        self.data_rw = data_rw

    def version(self, version):
        self.data_rw.version = version

    def size(self, size):
        if log.isEnabledFor(logging.INFO):
            log.info("Download size=[{}].".format(size))
        self.data_rw.size = size

    def data(self, position, data):
        self.data_rw.data_queue.put(data)

@asyncio.coroutine
def _send_get_data(data_key, significant_bits, data_rw):
    try:
        if significant_bits:
            future = asyncio.async(\
                node.chord_engine.tasks.send_find_key(\
                    data_key, significant_bits),
                loop=node.loop)

            yield from asyncio.wait_for(future, 15.0, loop=node.loop)

            ct_data_rw = future.result()

            data_key = ct_data_rw.data_key

            if log.isEnabledFor(logging.INFO):
                log.info("Found key=[{}].".format(mbase32.encode(data_key)))

            if not data_key:
                data_rw.data = b"Key Not Found"
                data_rw.version = -1
                data_rw.data_queue.put(None)
                return

            data_rw.data_key = bytes(data_key)
            data_rw.data_queue.put(None)
            return

#        future = asyncio.async(\
#            node.chord_engine.tasks.send_get_data(data_key),\
#            loop=node.loop)
#
#        yield from asyncio.wait_for(future, 15.0, loop=node.loop)
#
#        ct_data_rw = future.result()

        data_callback = Downloader(data_rw)

        r = yield from multipart.get_data(\
                node.chord_engine, data_key, data_callback, True)

        if r is False:
            raise asyncio.TimeoutError()
    except asyncio.TimeoutError:
        data_rw.timed_out = True
    except:
        log.exception("send_get_data()")
        data_rw.exception = True

    data_rw.data_queue.put(None)

@asyncio.coroutine
def _send_store_data(data, data_rw, privatekey=None, path=None, version=None):
    try:
        def key_callback(data_key):
            data_rw.data_key = data_key

        yield from multipart.store_data(node.chord_engine, data, privatekey,\
            path, version, key_callback)
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
        mbase32.encode(enc.generate_ID(static_upload_page_content[1]))

_set_upload_page(b'<html><head><title>Morphis Maalstroom Upload</title></head><body><p>Select the file to upload below:</p><form action="upload" method="post" enctype="multipart/form-data"><input type="file" name="fileToUpload" id="fileToUpload"/><div style="${UPDATEABLE_KEY_MODE_DISPLAY}"><br/><br/><label for="privateKey">Private Key</label><textarea name="privateKey" id="privateKey" rows="5" cols="80">${PRIVATE_KEY}</textarea><br/><label for="path">Path</label><input type="textfield" name="path" id="path"/><br/><label for="version">Version</label><input type="textfield" name="version" id="version"/></div><input type="submit" value="Upload File" name="submit"/></form><p style="${STATIC_MODE_DISPLAY}"><a href="morphis://upload/generate">switch to updateable key mode</a></p><p style="${UPDATEABLE_KEY_MODE_DISPLAY}"><a href="morphis://upload">switch to static key mode</a></p></body></html>')
