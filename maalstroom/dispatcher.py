import llog

import asyncio
import cgi
from enum import Enum
import importlib
import io
import logging
from threading import Event
import time
from urllib.parse import parse_qs, unquote

import base58
import chord
import enc
import maalstroom
import maalstroom.templates as templates
import mbase32
import multipart
import mutil
import rsakey

log = logging.getLogger(__name__)

class MaalstroomDispatcher(object):
    NO_DATA_MESSAGE = b"Data not found on network."

    def __init__(self, handler, inq, outq, abort_event):
        self.node = handler.node
        self.handler = handler

        self.loop = handler.loop

        self.inq = inq
        self.outq = outq

        self.client_engine = None

        self.finished_request = False

        self._abort_event = abort_event
        self._accept_charset = None
        self._charset = None

    @asyncio.coroutine
    def _ensure_client_engine(self):
        if self.client_engine:
            return

        self.client_engine = yield from maalstroom.get_client_engine()

    @property
    def connection_count(self):
        return len(self.node.chord_engine.peers)

    @property
    def latest_version_number(self):
        return self.client_engine.latest_version_number

    def send_response(self, code):
        # Maybe this should go through queue but then is less efficient and
        # this seems to work and is thread safe as we synchronized, it is only
        # a matter of if these are blocking calls, which i haven't checked in
        # the python source, but, in Linux sockets, there is no blocking
        # write in essence (buffered by kernel) so this should be find and
        # even optimal -- until we switch to asyncio http server. Abstracting
        # it from handler just in case and to make switching easier as
        # refactoring a non statically compiled language like Python is the
        # definition of pain.
        self.handler.send_response(code)

    def send_header(self, key, value):
        self.handler.send_header(key, value)

    def end_headers(self):
        self.handler.end_headers()

    def write(self, data):
        assert type(data) in (bytes, bytearray)
        self.outq.put(data)

    def flush(self):
        self.outq.put(maalstroom.Flush)

    def finish_response(self):
        self.outq.put(maalstroom.Done)
        self.finished_request = True

    @asyncio.coroutine
    def do_GET(self, rpath):
        self.finished_request = False

        self.rpath = rpath

        assert self.outq.empty()

        yield from self._ensure_client_engine()

        if not rpath:
            current_version = self.node.morphis_version

            latest_version_number = self.latest_version_number

            if latest_version_number\
                    and current_version != latest_version_number:
                version_str =\
                    '<span class="strikethrough nomargin">{}</span>]'\
                    '&nbsp;[<a href="{}{}">{} AVAILABLE</a>'\
                        .format(current_version,\
                            self.handler.maalstroom_url_prefix_str,\
                            "sp1nara3xhndtgswh7fznt414we4mi3y6kdwbkz4jmt8ocb6"\
                                "x4w1faqjotjkcrefta11swe3h53dt6oru3r13t667pr7"\
                                "cpe3ocxeuma/latest_version",\
                            latest_version_number)
            else:
                version_str = current_version

            content = templates.home_page_content[0].replace(\
                b"${CONNECTIONS}", str(self.connection_count).encode())
            content = content.replace(\
                b"${MORPHIS_VERSION}", version_str.encode())

            self.send_content([content, None])
            return

        if log.isEnabledFor(logging.DEBUG):
            log.debug("rpath=[{}].".format(rpath))

        if rpath[0] == '.':
            try:
                yield from self.dispatch_GET(rpath)
            except Exception as e:
                log.exception(\
                    "Exception serving GET: rpath=[{}]".format(rpath))
                self.send_exception(e)
        elif rpath == "favicon.ico":
            self.send_content(\
                templates.favicon_content, content_type="image/png")
        else:
            # At this point we assume it is a key URL.
            yield from self.dispatch_get_data(rpath)

        if not self.finished_request:
            log.warning("Request (rpath=[{}]) finished without calling"\
                " finish_response()!".format(rpath))

    @asyncio.coroutine
    def dispatch_GET(self, rpath):
        assert rpath[0] == '.'

        if rpath.startswith(".aiwj"):
            self.send_content(\
                b"AIWJ - Asynchronous IFrames Without Javascript!")
        elif rpath.startswith(".main/"):
            rpath = rpath[6:]
            if rpath == "style.css":
                self.send_content(\
                    templates.main_css, content_type="text/css")
#TODO: Have a UI where the user can enable this on a per portal basis only.
#            elif rpath == "csrf_token":
#                self.send_content(self.client_engine.csrf_token)
            else:
                self.send_error(errcode=400)
        elif rpath == ".images/favicon.ico":
            self.send_content(\
                templates.favicon_content, content_type="image/png")
        elif rpath.startswith(".upload") and maalstroom.upload_enabled:
            if rpath.startswith(".upload/generate"):
                priv_key =\
                    base58.encode(\
                        rsakey.RsaKey.generate(bits=4096)._encode_key())

                self.send_response(307)
                self.send_header("Location", "{}".format(priv_key))
                self.send_header("Content-Length", 0)
                self.end_headers()
                self.finish_response()
                return

            if rpath == ".upload" or rpath == ".upload/":
                if (self.handle_cache(rpath)):
                    return

                template = templates.main_combined_upload[0]

                template = template.format(\
                    csrf_token=self.client_engine.csrf_token,\
                    private_key="",\
                    version="",\
                    updateable_key_mode_display="display: none;",\
                    static_mode_display="")

                self.send_content(template)
            else:
                template = templates.main_combined_upload[0]

                # 8 = len(".upload/").
                template = template.format(\
                    csrf_token=self.client_engine.csrf_token,\
                    private_key=rpath[8:],\
                    version=str(int(time.time()*1000)),\
                    updateable_key_mode_display="",\
                    static_mode_display="display: none;")

                self.send_content(template)

        elif rpath.startswith(".dmail") and maalstroom.dmail_enabled:
            yield from maalstroom.dmail.serve_get(self, rpath)
        elif rpath.startswith(".dds") and maalstroom.dds_enabled:
            yield from maalstroom.dds.serve_get(self, rpath)
        elif rpath.startswith(".grok"):
            self.send_301(self.handler.maalstroom_url_prefix_str\
                + ".dds/axon/" + rpath[1:])
        elif rpath.startswith(MaalstroomDispatcher.ForceMode.HEX_DUMP.value):
            yield from self.dispatch_get_data(\
                rpath[len(MaalstroomDispatcher.ForceMode.HEX_DUMP.value):],\
                MaalstroomDispatcher.ForceMode.HEX_DUMP)
        elif rpath.startswith(MaalstroomDispatcher.ForceMode.PLAIN_TEXT.value):
            yield from self.dispatch_get_data(\
                rpath[len(MaalstroomDispatcher.ForceMode.PLAIN_TEXT.value):],\
                MaalstroomDispatcher.ForceMode.PLAIN_TEXT)
        else:
            self.send_error(errcode=400)

    @asyncio.coroutine
    def dispatch_get_data(self, rpath, force_mode=None):
        orig_etag = etag = self.handler.headers["If-None-Match"]
        if etag:
            updateable_key = etag.startswith("updateablekey-")
            if updateable_key:
                p0 = etag.index('-') + 1
                p1 = etag.find('-', p0)
                if p1 != -1:
                    version_from_etag = etag[p0:p1]
                    etag = etag[p1+1:]
                else:
                    version_from_etag = None
                    etag = etag[p0:]
        else:
            updateable_key = False
        if etag == rpath:
            # If browser has it cached.
            cache_control = self.handler.headers["Cache-Control"]
            if not (updateable_key and cache_control == "max-age=0")\
                    and cache_control != "no-cache":
                self.send_response(304)
                if updateable_key:
                    if version_from_etag:
                        self.send_header(\
                            "X-Maalstroom-UpdateableKey-Version",\
                            version_from_etag)
                    self.send_header("Cache-Control", "public,max-age=15")
                    self.send_header("ETag", orig_etag)
                else:
                    self.send_header(\
                        "Cache-Control", "public,max-age=315360000")
                    self.send_header("ETag", rpath)
                self.send_header("Content-Length", 0)
                self.end_headers()
                self.finish_response()
                return

        if not self.connection_count:
            self.send_error("No connected nodes; cannot fetch from the"\
                " network.")
            return

        path_sep_idx = rpath.find('/')
        if path_sep_idx != -1:
            path = rpath[path_sep_idx+1:].encode()
            rpath = rpath[:path_sep_idx]
        else:
            path = None

        if not rpath:
            msg = "Empty key was specified."
            log.warning(msg)
            self.send_error(msg, 400)
            return

        data_key, significant_bits = self.decode_key(rpath)

        if not data_key:
            self.send_error("Invalid encoded key: [{}].".format(rpath), 400)
            return

        if significant_bits:
            key = yield from self.fetch_key(data_key, significant_bits)

            if not key:
                return

            key_enc = mbase32.encode(key)

            url_prefix = self.handler.maalstroom_url_prefix_str
            if force_mode:
                url_prefix = url_prefix + force_mode.value

            if path:
                url = "{}{}/{}"\
                    .format(\
                        url_prefix,\
                        key_enc,\
                        path.decode("UTF-8"))
            else:
                url = "{}{}"\
                    .format(\
                        url_prefix,\
                        key_enc)

            message = "<html><head><title>Redirecting to Full Key</title>"\
                "</head><body><a href=\"{}\">{}</a>\n{}</body></html>"\
                    .format(url, url, key_enc).encode()

            self.send_301(url, message)
            return

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Sending GetData: key=[{}], path=[{}]."\
                .format(mbase32.encode(data_key), significant_bits, path))

        queue = asyncio.Queue(loop=self.loop)

        # Start the download.
        try:
            data_callback = Downloader(self, queue)

            @asyncio.coroutine
            def call_wrapper():
                try:
                    yield from multipart.get_data(\
                        self.node.chord_engine, data_key, data_callback,\
                        path=path, ordered=True)
                except Exception as e:
                    log.exception("multipart.get_data(..)")
                    data_callback.exception = e
                    data_callback.notify_finished(False)

            asyncio.async(call_wrapper(), loop=self.loop)
        except Exception as e:
            log.exception("send_get_data(..)")
            self.send_exception(e)
            return

        log.debug("Waiting for first data.")

        #TODO: This can be improved. Right now it causes the response to wait
        # for the first block of data to be fetched (which could be after a
        # few hash blocks are fetched) before it allows us to send the headers.
        # This would cause the browser to report the size rigth away instead of
        # seeming to take longer. It would require the response to be always be
        # chunked as we don't know until we get that first data if we are going
        # to rewrite or not. Such improvement wouldn't increase the speed or
        # anything so it can wait as it is only cosmetic likely.
        data = yield from queue.get()

        if data:
            if data is Error:
                if data_callback.success is None:
                    self.send_error(MaalstroomDispatcher.NO_DATA_MESSAGE, 404)
                else:
                    self.send_exception(data_callback.exception)
                return

            self.send_response(200)
            self.send_default_headers()

            rewrite_urls = False

            if force_mode:
                if force_mode is MaalstroomDispatcher.ForceMode.HEX_DUMP\
                        or force_mode\
                            is MaalstroomDispatcher.ForceMode.PLAIN_TEXT:
                    self.send_header("Content-Type", "text/plain")
                else:
                    assert False, force_mode
            elif data_callback.mime_type:
                self.send_header("Content-Type", data_callback.mime_type)
                if data_callback.mime_type\
                        in ("text/html", "text/css", "application/javascript"):
                    rewrite_urls = True
            else:
                dh = data[:160]

                if dh[0] == 0xFF and dh[1] == 0xD8:
                    self.send_header("Content-Type", "image/jpg")
                elif dh[0] == 0x89 and dh[1:4] == b"PNG":
                    self.send_header("Content-Type", "image/png")
                elif dh[:5] == b"GIF89":
                    self.send_header("Content-Type", "image/gif")
                elif dh[:5] == b"/*CSS":
                    self.send_header("Content-Type", "text/css")
                    rewrite_urls = True
                elif dh[:12] == b"/*JAVASCRIPT":
                    self.send_header("Content-Type", "application/javascript")
                    rewrite_urls = True
                elif dh[:8] == bytes(\
                        [0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70])\
                        or dh[:8] == bytes(\
                        [0x00, 0x00, 0x00, 0x1c, 0x66, 0x74, 0x79, 0x70]):
                    self.send_header("Content-Type", "video/mp4")
                elif dh[:8] == bytes(\
                        [0x50, 0x4b, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x00]):
                    self.send_header("Content-Type", "application/zip")
                elif dh[:5] == bytes(\
                        [0x25, 0x50, 0x44, 0x46, 0x2d]):
                    self.send_header("Content-Type", "application/pdf")
                elif dh[:4] == b"RIFF" and dh[8:11] == b"AVI":
                    self.send_header("Content-Type", "video/avi")
                else:
                    dhl = dh.lower()

                    if (dhl.find(b"<html") > -1 or dhl.find(b"<HTML>") > -1)\
                            and (dhl.find(b"<head>") > -1\
                                or dhl.find(b"<HEAD") > -1):
                        self.send_header("Content-Type", "text/html")
                        rewrite_urls = True
                    else:
                        self.send_header(\
                            "Content-Type", "application/octet-stream")

            rewrite_urls = rewrite_urls\
                and not self.handler.maalstroom_plugin_used

            if rewrite_urls:
                self.send_header("Transfer-Encoding", "chunked")
            else:
                if force_mode is not MaalstroomDispatcher.ForceMode.HEX_DUMP:
                    self.send_header("Content-Length", data_callback.size)

            if data_callback.version is not None:
                self.send_header(\
                    "X-Maalstroom-UpdateableKey-Version",\
                    data_callback.version)
                self.send_header("Cache-Control", "public,max-age=15")
                self.send_header(\
                    "ETag",\
                    "updateablekey-" + str(data_callback.version) + '-'\
                        + rpath)
            else:
                self.send_header("Cache-Control", "public,max-age=315360000")
                self.send_header("ETag", rpath)

            if force_mode is not MaalstroomDispatcher.ForceMode.HEX_DUMP:
                self.end_headers()

            hex_dump_buffer = bytearray()
            while True:
                if rewrite_urls:
                    self.send_partial_content(data)
                else:
                    if force_mode is MaalstroomDispatcher.ForceMode.HEX_DUMP:
                        hex_dump_buffer += data
                    else:
                        self.write(data)

                data = yield from queue.get()

                if data is None:
                    if rewrite_urls:
                        self.end_partial_content()
                    else:
                        if force_mode\
                                is MaalstroomDispatcher.ForceMode.HEX_DUMP:
                            dump = mutil.hex_dump(hex_dump_buffer).encode()
                            self.send_header("Content-Length", len(dump))
                            self.end_headers()
                            self.write(dump)
                        self.finish_response()
                    break
                elif data is Error:
                    if rewrite_urls:
                        self._fail_partial_content()
                    else:
                        if data_callback.success is None:
                            self.send_error(\
                                MaalstroomDispatcher.NO_DATA_MESSAGE, 404)
                        else:
                            self.close()
                    break

                if self._abort_event.is_set():
                    if log.isEnabledFor(logging.INFO):
                        log.info(\
                            "Maalstroom request got broken pipe from HTTP"\
                            " side; cancelling.")
                    data_callback.abort = True
                    break
        else:
            self.send_error(MaalstroomDispatcher.NO_DATA_MESSAGE, 404)

    def decode_key(self, rpath):
        try:
            return mutil.decode_key(rpath)
        except (ValueError, IndexError) as e:
            log.exception("mutil.decode_key(..), rpath=[{}].".format(rpath))
            return None, None

    @asyncio.coroutine
    def fetch_key(self, data_key, significant_bits):
        #TODO: Handle errors better as this was factored out of somewhere and
        # thus it directly sends the errors to the user instead of the calling
        # method doing that.

        # Resolve key via send_find_key.
        try:
            data_rw =\
                yield from asyncio.wait_for(\
                    self.node.chord_engine.tasks.send_find_key(\
                        data_key, significant_bits),\
                    15.0,\
                    loop=self.loop)
            data_key = data_rw.data_key
        except asyncio.TimeoutError:
            data_key = None

        if not data_key:
            self.send_error(b"Key Not Found", errcode=404)
            return None

        if log.isEnabledFor(logging.INFO):
            log.info("Found key=[{}].".format(mbase32.encode(data_key)))

        return data_rw.data_key

    @asyncio.coroutine
    def do_POST(self, rpath):
        self.finished_request = False

        self.rpath = rpath

        yield from self._ensure_client_engine()

        try:
            yield from self._do_POST(rpath)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            log.exception(\
                "Exception serving POST: rpath=[{}]".format(rpath))
            self.send_exception(e)

        if not self.finished_request:
            log.warning("Request (rpath=[{}]) finished without calling"\
                " finish_response()!".format(rpath))

    @asyncio.coroutine
    def _do_POST(self, rpath):
        log.info("POST; rpath=[{}].".format(rpath))

        if rpath.startswith(".dmail") and maalstroom.dmail_enabled:
            yield from maalstroom.dmail.serve_post(self, rpath)
            return
        elif rpath.startswith(".dds") and maalstroom.dds_enabled:
            yield from maalstroom.dds.serve_post(self, rpath)
            return

        if rpath != ".upload/upload" or not maalstroom.upload_enabled:
            self.send_error(errcode=400)
            return

        if not self.connection_count:
            self.send_error("No connected nodes; cannot upload to the"\
                " network.")
            return

        if log.isEnabledFor(logging.DEBUG):
            log.debug("headers=[{}].".format(self.handler.headers))

        version = None
        path = None
        mime_type = None

        if self.handler.headers["Content-Type"]\
                == "application/x-www-form-urlencoded":
            log.debug("Content-Type=[application/x-www-form-urlencoded].")

            user_agent = self.handler.headers["User-Agent"]

            if not (user_agent.startswith("curl/")\
                    or user_agent.startswith("Wget/")):
                self.send_error(\
                    "application/x-www-form-urlencoded uploads only allowed"\
                        " from Curl and Wget for CSRF protection reasons; use"\
                        " multipart/form-data instead.")
                return

            data = yield from self.read_request()
            privatekey = None
        else:
            if log.isEnabledFor(logging.DEBUG):
                log.debug("Content-Type=[{}]."\
                    .format(self.handler.headers["Content-Type"]))

            data = yield from self.read_request()

            form = cgi.FieldStorage(\
                fp=io.BytesIO(data),\
                headers=self.handler.headers,\
                environ={\
                    "REQUEST_METHOD": "POST",\
                    "CONTENT_TYPE": self.handler.headers["Content-Type"]})

            if log.isEnabledFor(logging.DEBUG):
                log.debug("form=[{}].".format(form))

            csrf_token = form["csrf_token"].value
            if not self.check_csrf_token(csrf_token):
                return

            formelement = form["fileToUpload"]
            filename = formelement.filename
            data = formelement.file.read()

            if log.isEnabledFor(logging.INFO):
                log.info("filename=[{}].".format(filename))

            privatekey = form["privateKey"].value

            if privatekey and privatekey != "${PRIVATE_KEY}":
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
            else:
                privatekey = None

        if log.isEnabledFor(logging.DEBUG):
            log.debug("data=[{}].".format(data))

        if not privatekey:
            assert not version and not path and not mime_type

        try:
            key_callback = KeyCallback()

            yield from multipart.store_data(\
                self.node.chord_engine, data, privatekey=privatekey,\
                path=path, version=version, key_callback=key_callback,\
                mime_type=mime_type)
        except asyncio.TimeoutError:
            self.send_error(errcode=408)
            return
        except Exception as e:
            log.exception("send_store_data(..)")
            self.send_exception(e)
            return

        if key_callback.data_key:
            enckey = mbase32.encode(key_callback.data_key)
            if privatekey and path:
                url = "{}{}/{}"\
                    .format(\
                        self.handler.maalstroom_url_prefix_str,\
                        enckey,\
                        path.decode("UTF-8"))
                short_url = "{}{}/{}"\
                    .format(\
                        self.handler.maalstroom_url_prefix_str,\
                        enckey[:32],\
                        path.decode("UTF-8"))
            else:
                url = "{}{}"\
                    .format(\
                        self.handler.maalstroom_url_prefix_str,\
                        enckey)
                short_url = "{}{}"\
                    .format(\
                        self.handler.maalstroom_url_prefix_str,\
                        enckey[:32])

            if privatekey:
                message =\
                    '<a id="key" href="{}">updateable key link</a><br/>'\
                        .format(url)
                message +=\
                    '<a id="short_key" href="{}">short updateable key link'\
                        '</a><br/>'\
                            .format(short_url)

                if key_callback.referred_key:
                    referred_key_enc =\
                        mbase32.encode(key_callback.referred_key)

                    message +=\
                        '<br/><a id="referred_key" href="{}{}">perma link</a>'\
                            '<br/>'\
                                .format(\
                                    self.handler.maalstroom_url_prefix_str,\
                                    referred_key_enc)
                    message +=\
                        '<a id="short_referred_key" href="{}{}">'\
                            'short perma link</a><br/>'\
                                .format(\
                                    self.handler.maalstroom_url_prefix_str,\
                                    referred_key_enc[:32])
            else:
                message = '<a id="key" href="{}">perma link</a><br/>'\
                    .format(url)
                message +=\
                    '<a id="short_key" href="{}">short perma link</a><br/>'\
                        .format(short_url)

            self.send_response(200)
            self.send_default_headers()
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", len(message))
            self.end_headers()

            self.write(bytes(message, "UTF-8"))
            self.finish_response()

    @asyncio.coroutine
    def read_request(self):
        #TODO: Improve this to stream input, but multipart.py needs to be
        # improved to handle a stream as input for uploads as well.
        datas = []
        inq = self.inq
        while True:
            data = yield from inq.get()
            if not data:
                break;
            datas.append(data)

        return b''.join(datas)

    @asyncio.coroutine
    def read_post(self):
        data = yield from self.read_request()

        if log.isEnabledFor(logging.DEBUG):
            log.debug("data=[{}].".format(data))

        charset = self.get_charset()

        qs = data.decode(charset)
        dd = parse_qs(qs, keep_blank_values=True)

        if log.isEnabledFor(logging.DEBUG):
            log.debug("dd=[{}].".format(dd))

        if not self.check_csrf_token(dd["csrf_token"][0]):
            return None

        return dd

    def get_charset(self):
        if self._charset:
            return self._charset

        charset = self.handler.headers["Content-Type"]
        if charset:
            p0 = charset.find("charset=")
            if p0 > -1:
                p0 += 8
                p1 = charset.find(' ', p0+8)
                if p1 == -1:
                    p1 = charset.find(';', p0+8)
                if p1 > -1:
                    charset = charset[p0:p1].strip()
                else:
                    charset = charset[p0:].strip()

                if log.isEnabledFor(logging.DEBUG):
                    log.debug("Form charset=[{}].".format(charset))
            else:
                charset = "UTF-8"

        self._charset = charset

        return charset

    def get_accept_charset(self):
        if self._accept_charset:
            return self._accept_charset

        acharset = self.handler.headers["Accept-Charset"]
        if acharset:
            if acharset.find("ISO-8859-1") > -1\
                    and acharset.find("UTF-8") == -1:
                acharset = "ISO-8859-1"
            else:
                acharset = "UTF-8"
        else:
            acharset = "UTF-8"

        self._accept_charset = acharset
        return acharset

    def send_default_headers(self):
        if self.handler.maalstroom_plugin_used:
            urls = self.handler.maalstroom_url_prefix_str + '* '\
                + self.handler.actual_url_prefix_str
        else:
            urls = "'self'"

        self.send_header(\
            "Content-Security-Policy",\
            "default-src 'unsafe-inline' 'unsafe-eval' " + urls)

    def send_204(self):
        "No content."
        self.send_response(204)
        self._send_no_cache()
        self.send_header("Content-Length", 0)
        self.end_headers()
        self.finish_response()

    def send_301(self, url, message=None):
        "Redirect."
        if not self.handler.maalstroom_plugin_used\
                and url.startswith("morphis://"):
            url = self.handler.maalstroom_url_prefix_str + url[10:]

        self.send_response(301)
        self.send_header("Location", url)

        if message:
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", len(message))
            self.end_headers()
            self.write(message)
        else:
            self.send_header("Content-Length", 0)
            self.end_headers()

        self.finish_response()

    def send_304(self, content_id, max_age=300):
        self.send_response(304)
        self.send_header("Cache-Control", "public,max-age={}".format(max_age))
        self.send_header("ETag", content_id)
        self.send_header("Content-Length", 0)
        self.end_headers()
        self.finish_response()

    def check_csrf_token(self, req_token):
        if maalstroom.disable_csrf_check:
            return True

        if self.client_engine.csrf_token == req_token:
            return True

        if log.isEnabledFor(logging.INFO):
            log.info("Invalid CSRF token!")

        self.send_error(\
            "Invalid csrf_token. If this was a valid request, then please"\
                " clear your browsers cache (shift reload will do).",\
            400)

        return False

    def handle_cache(self, content_id, max_age=300):
        if self.handler.headers["If-None-Match"] != content_id:
            return False

        self.send_304(content_id, max_age)

        return True

    def send_content(self, content_entry, cacheable=True, content_type=None,\
            charset=None):
        if type(content_entry) in (list, tuple):
            content = content_entry[0]
            content_id = content_entry[1]
            if len(content_entry) == 3 and not content_type:
                content_type = content_entry[2]
        else:
            content = content_entry
            cacheable = False

        if not content_type:
            if not charset:
                charset = self.get_accept_charset()
            content_type = "text/html; charset={}".format(charset)

        if type(content) is str:
            if charset:
                content = content.encode(charset)
            else:
                content = content.encode()

        if not self.handler.maalstroom_plugin_used:
            content =\
                content.replace(\
                    b"morphis://", self.handler.maalstroom_url_prefix)

        if cacheable and not content_id:
            if callable(content):
                content = content()
            log.info("Generating content_id.")
            content_id = mbase32.encode(enc.generate_ID(content))
            content_entry[1] = content_id

        etag = self.handler.headers["If-None-Match"]
        if cacheable and etag == content_id:
            cache_control = self.handler.headers["Cache-Control"]
            if cache_control != "no-cache":
                self.send_response(304)
                self.send_header("Cache-Control", "public,max-age=300")
                self.send_header("ETag", content_id)
                self.send_header("Content-Length", 0)
                self.end_headers()
                self.finish_response()
                return

        if callable(content):
            content = content()

        self.send_response(200)
        self.send_default_headers()
        self.send_header("Content-Length", len(content))
        self.send_header("Content-Type", content_type)
        if cacheable:
            self.send_header("Cache-Control", "public,max-age=300")
            self.send_header("ETag", content_id)
        else:
            self._send_no_cache()
        self.send_frame_options_header()
        self.end_headers()
        self.write(content)
        self.finish_response()
        return

    def send_frame_options_header(self):
        if self.handler.maalstroom_plugin_used:
            rpath = self.rpath
            if len(rpath) and rpath[0] == '.':
                p0 = rpath.find('/')
                if p0 != -1:
                    origin = rpath[:p0]
                else:
                    origin = ""
            else:
                origin = ""
            self.send_header(\
                "X-Frame-Options",\
                "ALLOW-FROM morphis://" + origin + '/')
        else:
            self.send_header(\
                "X-Frame-Options",\
                "ALLOW-FROM {}"\
                    .format(self.handler.maalstroom_url_prefix_str))

    def send_partial_content(self, content, start=False, content_type=None,\
            cacheable=False, charset=None):
        assert content is not None

        if not content_type:
            if not charset:
                charset = self.get_accept_charset()
            content_type = "text/html; charset={}".format(charset)

        if type(content) is str:
            if charset:
                content = content.encode(charset)
            else:
                content = content.encode()

        if not self.handler.maalstroom_plugin_used:
            content =\
                content.replace(\
                    b"morphis://", self.handler.maalstroom_url_prefix)

        if start:
            self.send_response(200)
            self.send_default_headers()
            if not cacheable:
                self._send_no_cache()
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Content-Type", content_type)
            self.send_frame_options_header()
            self.end_headers()

        chunklen = len(content)

#        if not content.endswith(b"\r\n"):
#            add_line = True
#            chunklen += 2
#        else:
#            add_line = False

        self.write("{:x}\r\n".format(chunklen).encode())
        self.write(content)
#        if add_line:
#            self.write(b"\r\n")
        self.write(b"\r\n")

        self.flush()

    def _fail_partial_content(self):
        log.info("Closing chunked response as failed.")
        self.write(b"1\r\n")
        self.close()

    def close(self):
        self.outq.put(maalstroom.Close)

    def end_partial_content(self):
        self.write(b"0\r\n\r\n")
        self.finish_response()

    def _send_no_cache(self):
        self.send_header("Cache-Control",\
            "no-cache, no-store, must-revalidate")
#            "private, no-store, max-age=0, no-cache, must-revalidate, post-check=0, pre-check=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
#        self.send_header("Expires", "Mon, 26 Jul 1997 00:00:00 GMT")
#        self.send_header("Last-Modified", "Sun, 2 Aug 2015 00:00:00 GMT")

    def send_exception(self, exception, errcode=500):
        self.send_error(\
            str("{}: {}".format(type(exception).__name__, exception)),\
            errcode=errcode)

    def send_error(self, msg=None, errcode=500, content_type=None):
        assert type(errcode) is int

        if errcode == 400:
            errmsg = b"400 Bad Request."
            self.send_response(400)
        elif errcode == 404:
            errmsg = b"404 Not Found."
            self.send_response(404)
        elif errcode == 408:
            errmsg = b"408 Request Timeout."
            self.send_response(408)
        else:
            errmsg = b"500 Internal Server Error."
            self.send_response(500)

        if msg:
            self.send_default_headers()

            if type(msg) is str:
                msg = msg.encode()

            if content_type:
                errmsg = msg
            else:
                content_type = "text/plain"
                errmsg += b"\n\n" + msg + b"\n"
        else:
            content_type = "text/plain"
            errmsg += b"\n"

        self.send_header("Content-Length", len(errmsg))
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.write(errmsg)
        self.finish_response()

    class ForceMode(Enum):
        HEX_DUMP = ".hexdump/"
        PLAIN_TEXT = ".text/"

class KeyCallback(multipart.KeyCallback):
    def __init__(self):
        self.data_key = None
        self.referred_key = None

    def notify_key(self, key):
        self.data_key = key

    def notify_referred_key(self, key):
        self.referred_key = key

##
# Wouldn't compile anymore and doesn't seem used.
#
#@asyncio.coroutine
#def _send_store_data(data, data_rw, privatekey=None, path=None, version=None,\
#        mime_type=""):
#
#    try:
#        key_callback = KeyCallback(data_rw)
#
#        yield from multipart.store_data(\
#            node.chord_engine, data, privatekey=privatekey, path=path,\
#            version=version, key_callback=key_callback, mime_type=mime_type)
#    except asyncio.TimeoutError:
#        data_rw.timed_out = True
#    except Exception:
#        log.exception("send_store_data(..)")
#        data_rw.exception = True
#
#    data_rw.is_done.set()

class Downloader(multipart.DataCallback):
    def __init__(self, dispatcher, queue):
        super().__init__()

        self.queue = queue

        self.version = None
        self.size = None
        self.mime_type = None

        self.abort = False

        self.exception = None
        self.success = None

    def notify_version(self, version):
        self.version = version

    def notify_size(self, size):
        if log.isEnabledFor(logging.INFO):
            log.info("Download size=[{}].".format(size))
        self.size = size

    def notify_mime_type(self, val):
        if log.isEnabledFor(logging.INFO):
            log.info("mime_type=[{}].".format(val))
        self.mime_type = val

    def notify_data(self, position, data):
        if self.abort:
            return False

        self.queue.put_nowait(data)

        return True

    def notify_finished(self, success):
        self.success = success

        if success:
            self.queue.put_nowait(None)
        else:
            self.queue.put_nowait(Error)

class Error(object):
    pass
