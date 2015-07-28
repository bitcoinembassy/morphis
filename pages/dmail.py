# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
import logging
import threading

from db import DmailAddress, DmailKey
import dmail
import mbase32
import mutil
import pages
import sshtype

log = logging.getLogger(__name__)

s_dmail = ".dmail"

def serve(handler, rpath):
    done_event = threading.Event()

    #FIXME: Is it safe to call the handler's out stream from the loop thread?
    # Because that is what I'm doing here.
    handler.node.loop.call_soon_threadsafe(\
        asyncio.async,\
        _serve(handler, rpath, done_event))

    done_event.wait()

@asyncio.coroutine
def _serve(handler, rpath, done_event):
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
        elif req.startswith("/addr/"):
            addr_enc = req[6:]

            if log.isEnabledFor(logging.INFO):
                log.info("Viewing dmail address [{}].".format(addr_enc))

            content = pages.dmail_address_page_content[0].replace(\
                b"${IFRAME_SRC}", "/inbox/{}".format(addr_enc).encode())

            handler._send_content((content, None), False)
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

            handler._send_content((content, None), False)
        elif req.startswith("/fetch/"):
            keys = req[7:]
            p0 = keys.index('/')
            dmail_addr_enc = keys[:p0]
            dmail_key_enc = keys[p0+1:]

            dmail_addr = mbase32.decode(dmail_addr_enc)
            dmail_key = mbase32.decode(dmail_key_enc)

            yield from _fetch_dmail(handler, dmail_addr, dmail_key)
        elif req == "/create_address":
            handler._send_content(pages.dmail_create_address_content, False)
        elif req == "/create_address/form":
            handler._send_content(\
                pages.dmail_create_address_form_content)
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

    done_event.set()

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

            return dmail_key_obj.target_id, dmail_key_obj.x

    target_id, x_bin = dbcall()
    l, x = sshtype.parseMpint(x_bin)

    dm = yield from de.fetch_dmail(bytes(dmail_key), x, target_id)

    if not dm:
        handler._send_partial_content(\
            "Dmail for key [{}] was not found."\
                .format(dmail_key_enc))
        return

    dmail_text = "Subject: {}\n".format(dm.subject)

    if dm.sender_pubkey:
        dmail_text += "From: {}\n"\
            .format(mbase32.encode(enc.generate_ID(dm.sender_pubkey)))

    dmail_text += '\n'

    i = 0
    for part in dm.parts:
        dmail_text += part.data.decode()
        dmail_text += '\n'

        if len(dm.parts) > 1:
            dmail_text += "----- ^ dmail part #{} ^ -----\n\n".format(i)
            i += 1

    handler._send_content(\
        (dmail_text.encode(), None), False, content_type="text/plain")

@asyncio.coroutine
def _create_dmail_address(handler, prefix):
    de = dmail.DmailEngine(handler.node.chord_engine.tasks, handler.node.db)
    privkey, data_key, dms = yield from de.generate_dmail_address(prefix)
    return privkey, data_key, dms
