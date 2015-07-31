# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
import importlib
import logging
import threading
import urllib

from db import DmailAddress, DmailKey
import dmail
import mbase32
import mutil
import pages
import sshtype

log = logging.getLogger(__name__)

s_dmail = ".dmail"

def serve_get(handler, rpath):
    done_event = threading.Event()

    #FIXME: Is it safe to call the handler's out stream from the loop thread?
    # Because that is what I'm doing here.
    handler.node.loop.call_soon_threadsafe(\
        asyncio.async,\
        _serve_get(handler, rpath, done_event))

    done_event.wait()

def serve_post(handler, rpath):
    done_event = threading.Event()

    #FIXME: Is it safe to call the handler's out stream from the loop thread?
    # Because that is what I'm doing here.
    handler.node.loop.call_soon_threadsafe(\
        asyncio.async,\
        _serve_post(handler, rpath, done_event))

    done_event.wait()

@asyncio.coroutine
def _serve_get(handler, rpath, done_event):
    try:
        yield from __serve_get(handler, rpath, done_event)
    except Exception as e:
        log.exception("__serve_get(..)")
        handler.send_exception(e)

    done_event.set()

@asyncio.coroutine
def _serve_post(handler, rpath, done_event):
    try:
        yield from __serve_post(handler, rpath, done_event)
    except Exception as e:
        log.exception("__serve_post(..)")
        handler.send_exception(e)

    done_event.set()

@asyncio.coroutine
def __serve_get(handler, rpath, done_event):
    if len(rpath) == len(s_dmail):
        handler._send_content(pages.dmail_page_content)
    else:
        req = rpath[len(s_dmail):]
        log.info("req=[{}].".format(req))
        if req == "/css":
            handler._send_content(\
                pages.dmail_css_content, content_type="text/css")
        elif req == "/address_list":
            handler._send_partial_content(
                pages.dmail_page_content__f1_start, True)

            _list_dmail_addresses(handler)

            handler._send_partial_content(pages.dmail_page_content__f1_end)
            handler._end_partial_content()
        elif req == "/compose":
            from_addr = req[9:]

            handler._send_content(pages.dmail_compose_dmail_content)
        elif req == "/compose/form":
            handler._send_content(pages.dmail_compose_dmail_form_content)
        elif req.startswith("/addr/"):
            addr_enc = req[6:]

            if log.isEnabledFor(logging.INFO):
                log.info("Viewing dmail address [{}].".format(addr_enc))

            content = pages.dmail_address_page_content[0].replace(\
                b"${IFRAME_SRC}", "/inbox/{}".format(addr_enc).encode())

            handler._send_content(content)
        elif req.startswith("/inbox/"):
            addr_enc = req[7:]

            if log.isEnabledFor(logging.INFO):
                log.info("Viewing inbox for dmail address [{}]."\
                    .format(addr_enc))

            start = pages.dmail_inbox_start.replace(\
                b"${DMAIL_ADDRESS}", "{}...".format(addr_enc[:32]).encode())
            handler._send_partial_content(start, True)

            addr = bytes(mbase32.decode(addr_enc))

            yield from _list_dmail_inbox(handler, addr)

            handler._send_partial_content(pages.dmail_inbox_end)
            handler._end_partial_content()
        elif req.startswith("/view/"):
            req_data = req[6:]

            content = pages.dmail_address_page_content[0].replace(\
                b"${IFRAME_SRC}", "/fetch/{}".format(req_data).encode())

            handler._send_content(content)
        elif req.startswith("/fetch/"):
            keys = req[7:]
            p0 = keys.index('/')
            dmail_addr_enc = keys[:p0]
            dmail_key_enc = keys[p0+1:]

            dmail_addr = mbase32.decode(dmail_addr_enc)
            dmail_key = mbase32.decode(dmail_key_enc)

            yield from _fetch_dmail(handler, dmail_addr, dmail_key)
        elif req == "/create_address":
            handler._send_content(pages.dmail_create_address_content)
        elif req == "/create_address/form":
            handler._send_content(pages.dmail_create_address_form_content)
        elif req.startswith("/create_address/make_it_so"):
            prefix = req[26 + 1 + 7:] # + ?prefix=
            log.info("prefix=[{}].".format(prefix))
            privkey, dmail_key, dms =\
                yield from _create_dmail_address(handler, prefix)

            dmail_key_enc = mbase32.encode(dmail_key)

            handler._send_partial_content(pages.dmail_frame_start, True)
            handler._send_partial_content(b"SUCCESS<br/>")
            handler._send_partial_content(\
                """<p>New dmail address: <a href="../addr/{}">{}</a></p>"""\
                    .format(dmail_key_enc, dmail_key_enc).encode())
            handler._send_partial_content(pages.dmail_frame_end)
            handler._end_partial_content()
        else:
            handler._handle_error()

@asyncio.coroutine
def __serve_post(handler, rpath, done_event):
    assert rpath.startswith(s_dmail)

    rpath = rpath[len(s_dmail):]

    if rpath == "/compose/make_it_so":
        data = handler.rfile.read(int(handler.headers["Content-Length"]))
        log.debug("data=[{}].".format(data))
        dd = urllib.parse.parse_qs(data)
        log.debug("dd=[{}].".format(dd))

        subject = dd.get(b"subject")
        if subject:
            subject = subject[0].decode()
        else:
            subject = ""

#        sender_asymkey = rsakey.RsaKey(privdata=base58.decode(dd[b"sender"])
        sender_asymkey = None

        dest_addr_enc = dd.get(b"destination")
        if not dest_addr_enc:
            handler._send_error("You must specify a destination.", 400)
            return

        recipient, significant_bits =\
            mutil.decode_key(dest_addr_enc[0].decode())
        recipients = [(dest_addr_enc, recipient, significant_bits)]

        content = dd.get(b"content")
        if content:
            content = content[0]

        de = dmail.DmailEngine(handler.node.chord_engine.tasks)
        yield from de.send_dmail(\
            sender_asymkey,\
            recipients,\
            subject,\
            None,\
            content)

        handler._send_content(\
            "SUCCESS.<br/><p>Dmail successfully sent to: {}</p>"\
                .format(dest_addr_enc[0].decode()).encode())
    else:
        handler._handle_error()

def _list_dmail_addresses(handler):
    def dbcall():
        with handler.node.db.open_session() as sess:
            q = sess.query(DmailAddress)

            log.info("Fetching addresses...")

            for addr in mutil.page_query(q):
                site_key_enc = mbase32.encode(addr.site_key)

                resp = """<a href="addr/{}">{}</a><br/>"""\
                    .format(site_key_enc, site_key_enc)

                handler._send_partial_content(resp)

            sess.rollback()

    dbcall()

@asyncio.coroutine
def _list_dmail_inbox(handler, addr):
    de = dmail.DmailEngine(handler.node.chord_engine.tasks)

    def key_callback(key):
        addr_enc = mbase32.encode(addr)
        key_enc = mbase32.encode(key)
        handler._send_partial_content(\
            """<a href="../view/{}/{}">{}</a><br/>"""\
                .format(addr_enc, key_enc, key_enc))

    try:
        yield from de.scan_dmail_address(addr, key_callback=key_callback)
    except dmail.DmailException as e:
        handler._send_partial_content("DmailException: {}".format(e))

@asyncio.coroutine
def _fetch_dmail(handler, dmail_addr, dmail_key):
    de = dmail.DmailEngine(handler.node.chord_engine.tasks)

    if log.isEnabledFor(logging.INFO):
        dmail_key_enc = mbase32.encode(dmail_key)
        dmail_addr_enc = mbase32.encode(dmail_addr)
        log.info("Fetching dmail (key=[{}]) for address=[{}]."\
            .format(dmail_key_enc, dmail_addr_enc))

    def dbcall():
        nonlocal dmail_addr

        with handler.node.db.open_session() as sess:
            q = sess.query(DmailAddress)\
                .filter(DmailAddress.site_key == dmail_addr)

            dmail_addr_obj = q.first()
            dmail_key_obj = dmail_addr_obj.dmail_keys[0]

            sess.rollback()

            return dmail_key_obj.target_key, dmail_key_obj.x

    target_key, x_bin = dbcall()
    l, x = sshtype.parseMpint(x_bin)

    dm = yield from de.fetch_dmail(bytes(dmail_key), x, target_key)

    if not dm:
        handler._send_partial_content(\
            "Dmail for key [{}] was not found."\
                .format(dmail_key_enc))
        return

    dmail_text = []

    if dm.sender_pubkey:
        dmail_text += "From: {}\n"\
            .format(mbase32.encode(enc.generate_ID(dm.sender_pubkey)))

    dmail_text += "Subject: {}\n".format(dm.subject)

    date_fmtted = mutil.parse_iso_datetime(dm.date)
    dmail_text += "Date: {}\n".format(date_fmtted)

    dmail_text += '\n'

    i = 0
    for part in dm.parts:
        dmail_text += part.data.decode()
        dmail_text += '\n'

        if len(dm.parts) > 1:
            dmail_text += "----- ^ dmail part #{} ^ -----\n\n".format(i)
            i += 1

    dmail_text = ''.join(dmail_text)

    handler._send_content(dmail_text.encode(), content_type="text/plain")

@asyncio.coroutine
def _create_dmail_address(handler, prefix):
    de = dmail.DmailEngine(handler.node.chord_engine.tasks, handler.node.db)
    privkey, data_key, dms = yield from de.generate_dmail_address(prefix)
    return privkey, data_key, dms
