# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
import cgi
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib
import logging
import queue
from socketserver import ThreadingMixIn
from threading import Event
import time

import base58
import chord
import enc
import rsakey
import mbase32
import pages
import pages.dmail
import multipart
import mutil

log = logging.getLogger(__name__)

host = "localhost"
port = 4251

node = None
server = None

upload_page_content = None
static_upload_page_content = [None, None]

class DataResponseWrapper(object):
    def __init__(self):
        self.data = None
        self.size = None

        self.data_key = None

        self.path = None
        self.version = None
        self.mime_type = None

        self.is_done = Event()
        self.data_queue = queue.Queue()

        self.exception = None
        self.timed_out = False

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class MaalstroomHandler(BaseHTTPRequestHandler):
    def __init__(self, a, b, c):
        global node
        self.protocol_version = "HTTP/1.1"
        self.node = node

        self.maalstroom_plugin_used = False
        self.maalstroom_url_prefix = None
        self._maalstroom_http_url_prefix = "http://{}/"
        self._maalstroom_morphis_url_prefix = "morphis://"

        super().__init__(a, b, c)

    def __prepare_for_request(self):
        if self.headers["X-Maalstroom-Plugin"]:
            self.maalstroom_plugin_used = True
            self.maalstroom_url_prefix =\
                self._maalstroom_morphis_url_prefix.encode()
        else:
            global port
            host = self.headers["Host"]
            if log.isEnabledFor(logging.DEBUG):
                log.debug("No plugin used for request, rewriting URLs using"\
                    " host=[{}]."\
                        .format(host))
            # Host header includes port.
            self.maalstroom_url_prefix =\
                self._maalstroom_http_url_prefix.format(host).encode()

    def __get_connection_count(self, q):
        cnt = len(self.node.chord_engine.peers)
        q.put(cnt)

    def _get_connection_count(self):
        q = queue.Queue()

        self.node.loop.call_soon_threadsafe(self.__get_connection_count, q)

        return q.get()

    def do_GET(self):
        self.__prepare_for_request()

        rpath = self.path[1:]

        if rpath and rpath[-1] == '/':
            rpath = rpath[:-1]

        connection_cnt = None

        if not rpath:
            connection_cnt = self._get_connection_count()

            content = pages.home_page_content[0].replace(\
                b"${CONNECTIONS}", str(connection_cnt).encode())
            self._send_content([content, None])
            return

        s_upload = ".upload"
        s_dmail = ".dmail"
        s_aiwj = ".aiwj"

        if log.isEnabledFor(logging.DEBUG):
            log.debug("rpath=[{}].".format(rpath))

        if rpath.startswith(s_aiwj):
            self._send_content(\
                b"AIWJ - Asynchronous IFrames Without Javascript!")
            return
        elif rpath.startswith(s_upload):
            if rpath.startswith(".upload/generate"):
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
        elif rpath.startswith(s_dmail):
            if self.node.web_devel:
                importlib.reload(pages)
                importlib.reload(pages.dmail)

            pages.dmail.serve_get(self, rpath)
            return

        if self.headers["If-None-Match"] == rpath:
            self.send_response(304)
            self.send_header("ETag", rpath)
            self.send_header("Content-Length", 0)
            self.end_headers()
            return

        error = False

        significant_bits = None

        # At this point we assume it is a key URL.

        if connection_cnt is None:
            connection_cnt = self._get_connection_count()
        if not connection_cnt:
            self.send_exception("No connected nodes; cannot fetch from the"\
                " network.")
            return

        path_sep_idx = rpath.find('/')
        if path_sep_idx != -1:
            path = rpath[path_sep_idx+1:].encode()
            rpath = rpath[:path_sep_idx]
        else:
            path = None

        try:
            data_key, significant_bits = mutil.decode_key(rpath)
        except:
            error = True
            log.exception("decode")

        if error:
            self._handle_error()
            return

        data_rw = DataResponseWrapper()

        self.node.loop.call_soon_threadsafe(\
            asyncio.async,\
            _send_get_data(data_key, significant_bits, path, data_rw))

        data = data_rw.data_queue.get()

        if significant_bits:
            if data_rw.data_key:
                key = mbase32.encode(data_rw.data_key)

                if path:
                    url = "{}{}/{}"\
                        .format(\
                            self.maalstroom_url_prefix.decode(),\
                            key,\
                            path.decode("UTF-8"))
                else:
                    url = "{}{}"\
                        .format(\
                            self.maalstroom_url_prefix.decode(),\
                            key)

                message = ("<html><head><title>permalink</title></head><body><a href=\"{}\">{}</a>\n{}</body></html>"\
                    .format(url, url, key))\
                        .encode()

                self.send_response(301)
                self.send_header("Location", url)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", len(message))
                self.end_headers()

                self.wfile.write(message)
                return

        if data:
            self.send_response(200)

            rewrite_url = False

            if data_rw.mime_type:
                self.send_header("Content-Type", data_rw.mime_type)
                if not self.maalstroom_plugin_used and data_rw.mime_type\
                        in ("text/html", "text/css", "application/javascript"):
                    rewrite_url = True
            else:
                if data[0] == 0xFF and data[1] == 0xD8:
                    self.send_header("Content-Type", "image/jpg")
                elif data[0] == 0x89 and data[1:4] == b"PNG":
                    self.send_header("Content-Type", "image/png")
                elif data[:5] == b"GIF89":
                    self.send_header("Content-Type", "image/gif")
                elif data[:5] == b"/*CSS":
                    self.send_header("Content-Type", "text/css")
                    rewrite_url = True
                elif data[:12] == b"/*JAVASCRIPT":
                    self.send_header("Content-Type", "application/javascript")
                    rewrite_url = True
                elif data[:8] == bytes(\
                        [0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70]):
                    self.send_header("Content-Type", "video/mp4")
                elif data[:8] == bytes(\
                        [0x50, 0x4b, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x00]):
                    self.send_header("Content-Type", "application/zip")
                else:
                    self.send_header("Content-Type", "text/html")
                    rewrite_url = True

            self.send_header("Content-Length", data_rw.size)

            if data_rw.version is not None:
                self.send_header("Cache-Control", "max-age=15, public")
            else:
                self.send_header("Cache-Control", "public")
                self.send_header("ETag", rpath)

            self.end_headers()

            while True:
                if rewrite_url:
                    self.wfile.write(\
                        data.replace(b"morphis://",\
                            self.maalstroom_url_prefix))
                else:
                    self.wfile.write(data)

                data = data_rw.data_queue.get()

                if data is None:
                    break
        else:
            self._handle_error(data_rw)

    def do_POST(self):
        self.__prepare_for_request()

        rpath = self.path[1:]

        log.info("POST; rpath=[{}].".format(rpath))

        if rpath != ".upload/upload":
            pages.dmail.serve_post(self, rpath)
            return

        if log.isEnabledFor(logging.DEBUG):
            log.info(self.headers)

        if self.headers["Content-Type"] == "application/x-www-form-urlencoded":
            log.debug("Content-Type=[application/x-www-form-urlencoded].")
            data = self.rfile.read(int(self.headers["Content-Length"]))
            privatekey = None
        else:
            if log.isEnabledFor(logging.DEBUG):
                log.debug("Content-Type=[{}]."\
                    .format(self.headers["Content-Type"]))

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
                mime_type = form["mime_type"].value
            except KeyError:
                privatekey = None

        if log.isEnabledFor(logging.DEBUG):
            log.debug("data=[{}].".format(data))

        data_rw = DataResponseWrapper()

        if privatekey:
            node.loop.call_soon_threadsafe(\
                asyncio.async, _send_store_data(\
                    data, data_rw, privatekey, path, version, mime_type))
        else:
            node.loop.call_soon_threadsafe(\
                asyncio.async, _send_store_data(data, data_rw))

        data_rw.is_done.wait()

        if data_rw.data_key:
            enckey = mbase32.encode(data_rw.data_key)
            if privatekey and path:
                url = "{}{}/{}"\
                    .format(\
                        self.maalstroom_url_prefix.decode(),\
                        enckey,\
                        path.decode("UTF-8"))
            else:
                url = "{}{}"\
                    .format(\
                        self.maalstroom_url_prefix.decode(),\
                        enckey)

            message = '<a href="{}">perma link</a>'.format(url)

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", len(message))
            self.end_headers()

            self.wfile.write(bytes(message, "UTF-8"))
        else:
            self._handle_error(data_rw)

    def _send_204(self):
        self.send_response(204)
        self.send_header("Content-Length", 0)
        self.end_headers()
        return

    def _send_content(self, content_entry, cacheable=True, content_type=None):
        if type(content_entry) in (list, tuple):
            content = content_entry[0]
            content_id = content_entry[1]
        else:
            content = content_entry
            cacheable = False

        if not self.maalstroom_plugin_used:
            content =\
                content.replace(b"morphis://", self.maalstroom_url_prefix)

        if cacheable and not content_id:
            if callable(content):
                content = content()
            content_id = mbase32.encode(enc.generate_ID(content))
            content_entry[1] = content_id

        if cacheable and self.headers["If-None-Match"] == content_id:
            self.send_response(304)
            self.send_header("ETag", content_id)
            self.send_header("Content-Length", 0)
            self.end_headers()
            return

        if callable(content):
            content = content()

        self.send_response(200)
        self.send_header("Content-Length", len(content))
        self.send_header("Content-Type",\
            "text/html" if content_type is None else content_type)
        if cacheable:
            self.send_header("Cache-Control", "public")
            self.send_header("ETag", content_id)
        else:
            self._send_no_cache()

        self.end_headers()
        self.wfile.write(content)
        return

    def _send_partial_content(self, content, start=False, content_type=None,\
            cacheable=False):
        if type(content) is str:
            content = content.encode()

        if not self.maalstroom_plugin_used:
            content =\
                content.replace(b"morphis://", self.maalstroom_url_prefix)

        if start:
            self.send_response(200)
            if not cacheable:
                self._send_no_cache()
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Content-Type",\
                "text/html" if content_type is None else content_type)
            self.end_headers()

        chunklen = len(content)

#        if not content.endswith(b"\r\n"):
#            add_line = True
#            chunklen += 2
#        else:
#            add_line = False

        self.wfile.write("{:x}\r\n".format(chunklen).encode())
        self.wfile.write(content)
#        if add_line:
#            self.wfile.write(b"\r\n")
        self.wfile.write(b"\r\n")

        self.wfile.flush()

    def _end_partial_content(self):
        self.wfile.write(b"0\r\n\r\n")

    def _send_no_cache(self):
        self.send_header("Cache-Control",\
            "no-cache, no-store, must-revalidate")
#            "private, no-store, max-age=0, no-cache, must-revalidate, post-check=0, pre-check=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
#        self.send_header("Expires", "Mon, 26 Jul 1997 00:00:00 GMT")
#        self.send_header("Last-Modified", "Sun, 2 Aug 2015 00:00:00 GMT")

    def send_exception(self, exception, errcode=500):
        self._send_error(\
            errmsg=str("{}: {}".format(type(exception).__name__, exception)),\
            errcode=errcode)

    def _send_error(self, errmsg, errcode=500):
        if errcode == 400:
            errmsg = "400 Bad Request.\n\n{}"\
                .format(errmsg).encode()
            self.send_response(400)
        else:
            errmsg = "500 Internal Server Error.\n\n{}"\
                .format(errmsg).encode()
            self.send_response(500)

        self.send_header("Content-Length", len(errmsg))
        self.end_headers()
        self.wfile.write(errmsg)

    def _handle_error(self, data_rw=None, errmsg=None, errcode=None):
        if not data_rw:
            errmsg = b"400 Bad Request."
            self.send_response(400)
        elif data_rw.exception:
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

    def notify_version(self, version):
        self.data_rw.version = version

    def notify_size(self, size):
        if log.isEnabledFor(logging.INFO):
            log.info("Download size=[{}].".format(size))
        self.data_rw.size = size

    def notify_mime_type(self, val):
        if log.isEnabledFor(logging.INFO):
            log.info("mime_type=[{}].".format(val))
        self.data_rw.mime_type = val

    def notify_data(self, position, data):
        self.data_rw.data_queue.put(data)

@asyncio.coroutine
def _send_get_data(data_key, significant_bits, path, data_rw):
    if log.isEnabledFor(logging.DEBUG):
        log.debug(\
            "Sending GetData: key=[{}], significant_bits=[{}], path=[{}]."\
                .format(mbase32.encode(data_key), significant_bits, path))

    try:
        if significant_bits:
            future = asyncio.async(\
                node.chord_engine.tasks.send_find_key(\
                    data_key, significant_bits),
                loop=node.loop)

            yield from asyncio.wait_for(future, 15.0, loop=node.loop)

            ct_data_rw = future.result()

            data_key = ct_data_rw.data_key

            if not data_key:
                data_rw.data = b"Key Not Found"
                data_rw.version = -1
                data_rw.data_queue.put(None)
                return

            if log.isEnabledFor(logging.INFO):
                log.info("Found key=[{}].".format(mbase32.encode(data_key)))

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
                node.chord_engine, data_key, data_callback, path=path,
                ordered=True)

        if r is False:
            raise asyncio.TimeoutError()
    except asyncio.TimeoutError:
        data_rw.timed_out = True
    except:
        log.exception("send_get_data(..)")
        data_rw.exception = True

    data_rw.data_queue.put(None)

@asyncio.coroutine
def _send_store_data(data, data_rw, privatekey=None, path=None, version=None,\
        mime_type=""):
    try:
        def key_callback(data_key):
            data_rw.data_key = data_key

        yield from multipart.store_data(\
            node.chord_engine, data, privatekey=privatekey, path=path,\
            version=version, key_callback=key_callback, mime_type=mime_type)
    except asyncio.TimeoutError:
        data_rw.timed_out = True
    except:
        log.exception("send_store_data(..)")
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
        mbase32.encode(enc.generate_ID(static_upload_page_content[0]))

_set_upload_page(b'<html><head><title>MORPHiS Maalstroom Upload</title></head><body><h4 style="${UPDATEABLE_KEY_MODE_DISPLAY}">NOTE: Bookmark this page to save your private key in the bookmark!</h4>Select the file to upload below:</p><form action="upload" method="post" enctype="multipart/form-data"><input type="file" name="fileToUpload" id="fileToUpload"/><div style="${UPDATEABLE_KEY_MODE_DISPLAY}"><br/><br/><label for="privateKey">Private Key</label><textarea name="privateKey" id="privateKey" rows="5" cols="80">${PRIVATE_KEY}</textarea><br/><label for="path">Path</label><input type="textfield" name="path" id="path"/><br/><label for="version">Version</label><input type="textfield" name="version" id="version"/><br/><label for="mime_type">Mime Type</label><input type="textfield" name="mime_type" id="mime_type"/><br/></div><input type="submit" value="Upload File" name="submit"/></form><p style="${STATIC_MODE_DISPLAY}"><a href="morphis://.upload/generate">switch to updateable key mode</a></p><p style="${UPDATEABLE_KEY_MODE_DISPLAY}"><a href="morphis://.upload/">switch to static key mode</a></p><h5><- <a href="morphis://">MORPHiS UI</a></h5></body></html>')
