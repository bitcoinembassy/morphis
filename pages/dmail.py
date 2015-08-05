# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
import logging
import threading
import time
import urllib.parse

from sqlalchemy import func, not_
from sqlalchemy.orm import joinedload

import base58
from db import DmailAddress, DmailKey, DmailMessage, DmailTag, DmailPart
import dhgroup14
import enc
import dmail
import mbase32
import mutil
import pages
import rsakey
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

            site_keys = yield from _list_dmail_addresses(handler)

            for dbid, site_key in site_keys:
                site_key_enc = mbase32.encode(site_key)

                resp = """<span class="nowrap">[<a href="addr/{}">view</a>]"""\
                    """ {}</span><br/>"""\
                        .format(site_key_enc, site_key_enc)

                handler._send_partial_content(resp)

            handler._send_partial_content(pages.dmail_page_content__f1_end)
            handler._end_partial_content()
        elif req.startswith("/compose/form"):
            dest_addr_enc = req[14:] if len(req) > 14 else ""

            handler._send_partial_content(\
                pages.dmail_compose_dmail_form_start, True)

            site_keys = yield from _list_dmail_addresses(handler)

            for dbid, site_key in site_keys:
                site_key_enc = mbase32.encode(site_key)

                sender_element = """<option value="{}">{}</option>"""\
                    .format(dbid, site_key_enc)

                handler._send_partial_content(sender_element)

            handler._send_partial_content(\
                "<option value="">[Anonymous]</option>")

            handler._send_partial_content(\
                pages.dmail_compose_dmail_form_end.replace(\
                    b"${DEST_ADDR}", dest_addr_enc.encode()))

            handler._end_partial_content()
        elif req.startswith("/compose"):
            from_addr = req[9:]

            if from_addr:
                iframe_src = "compose/form/{}".format(from_addr).encode()
            else:
                iframe_src = "compose/form".encode()

            content = pages.dmail_compose_dmail_content[0].replace(\
                    b"${IFRAME_SRC}", iframe_src)

            handler._send_content([content, None])
        elif req.startswith("/addr/view/"):
            addr_enc = req[11:]

            start = pages.dmail_addr_view_start.replace(\
                b"${DMAIL_ADDRESS}", addr_enc.encode())
            start = start.replace(\
                b"${DMAIL_ADDRESS_SHORT}", addr_enc[:32].encode())

            handler._send_partial_content(start, True)

            handler._send_partial_content(pages.dmail_addr_view_end)
            handler._end_partial_content()
        elif req.startswith("/addr/settings/edit/publish?"):
            query = req[28:]

            qdict = urllib.parse.parse_qs(query)

            addr_enc = qdict["dmail_address"][0]
            difficulty = qdict["difficulty"][0]

            def processor(dmail_address):
                if difficulty != dmail_address.keys[0].difficulty:
                    dmail_address.keys[0].difficulty = difficulty
                    return True
                else:
                    return False

            dmail_address = yield from\
                _process_dmail_address(\
                    handler, mbase32.decode(addr_enc), processor)

            dh = dhgroup14.DhGroup14()
            dh.x = sshtype.parseMpint(dmail_address.keys[0].x)[1]
            dh.generate_e()

            dms = dmail.DmailSite()
            root = dms.root
            root["target"] =\
                mbase32.encode(dmail_address.keys[0].target_key)
            root["difficulty"] = int(difficulty)
            root["ssm"] = "mdh-v1"
            root["sse"] = base58.encode(sshtype.encodeMpint(dh.e))

            private_key = rsakey.RsaKey(privdata=dmail_address.site_privatekey)

            r = yield from\
                handler.node.chord_engine.tasks.send_store_updateable_key(\
                    dms.export(), private_key,\
                    version=int(time.time()*1000), store_key=True)

            handler._send_content(\
                pages.dmail_addr_settings_edit_success_content[0]\
                    .format(addr_enc, addr_enc[:32]).encode())
        elif req.startswith("/addr/settings/edit/"):
            addr_enc = req[20:]

            dmail_address = yield from\
                _load_dmail_address(handler, mbase32.decode(addr_enc))

            content = pages.dmail_addr_settings_edit_content[0].replace(\
                b"${DIFFICULTY}",\
                str(dmail_address.keys[0].difficulty).encode())
            content = content.replace(\
                b"${DMAIL_ADDRESS_SHORT}", addr_enc[:32].encode())
            content = content.replace(\
                b"${DMAIL_ADDRESS}", addr_enc.encode())
            content = content.replace(\
                b"${PRIVATE_KEY}",\
                base58.encode(dmail_address.site_privatekey).encode())
            content = content.replace(\
                b"${X}", base58.encode(dmail_address.keys[0].x).encode())
            content = content.replace(\
                b"${TARGET_KEY}",\
                base58.encode(dmail_address.keys[0].target_key).encode())

            handler._send_content([content, None])
        elif req.startswith("/addr/settings/"):
            addr_enc = req[15:]

            content = pages.dmail_addr_settings_content[0].replace(\
                b"${IFRAME_SRC}",\
                "edit/{}".format(addr_enc).encode())

            handler._send_content([content, None])
        elif req.startswith("/addr/"):
            addr_enc = req[6:]

            if log.isEnabledFor(logging.INFO):
                log.info("Viewing dmail address [{}].".format(addr_enc))

            content = pages.dmail_address_page_content[0].replace(\
                b"${IFRAME_SRC}", "view/{}".format(addr_enc).encode())

            handler._send_content([content, None])
        elif req.startswith("/tag/view/list/"):
            params = req[15:]

            p0 = params.index('/')
            tag = params[:p0]
            addr_enc = params[p0+1:]

            if log.isEnabledFor(logging.INFO):
                log.info("Viewing dmails with tag [{}] for address [{}]."\
                    .format(tag, addr_enc))

            start = pages.dmail_tag_view_list_start.replace(\
                b"${TAG_NAME}", tag.encode())
            #FIXME: This is getting inefficient now, maybe time for Flask or
            # something like it. Maybe we can use just it's template renderer.
            start = start.replace(b"${DMAIL_ADDRESS}", addr_enc.encode())
            start = start.replace(\
                b"${DMAIL_ADDRESS2}",\
                "{}...".format(addr_enc[:32]).encode())

            handler._send_partial_content(start, True)

            yield from\
                _list_dmails_for_tag(handler, mbase32.decode(addr_enc), tag)

            handler._send_partial_content(pages.dmail_tag_view_list_end)
            handler._end_partial_content()

        elif req.startswith("/tag/view/"):
            params = req[10:]

            content = pages.dmail_tag_view_content[0].replace(\
                b"${IFRAME_SRC}", "../list/{}".format(params).encode())

            handler._send_content(content)
        elif req.startswith("/scan/list/"):
            addr_enc = req[11:]

            if log.isEnabledFor(logging.INFO):
                log.info("Viewing inbox for dmail address [{}]."\
                    .format(addr_enc))

            start = pages.dmail_inbox_start.replace(\
                b"${DMAIL_ADDRESS}", addr_enc.encode())
            start = start.replace(\
                b"${DMAIL_ADDRESS2}", "{}...".format(addr_enc[:32]).encode())

            handler._send_partial_content(start, True)

            addr, significant_bits = mutil.decode_key(addr_enc)

            yield from _scan_new_dmails(handler, addr, significant_bits)

            handler._send_partial_content(pages.dmail_inbox_end)
            handler._end_partial_content()
        elif req.startswith("/scan/"):
            addr_enc = req[6:]

            content = pages.dmail_address_page_content[0].replace(\
                b"${IFRAME_SRC}", "list/{}".format(addr_enc).encode())

            handler._send_content([content, None])
        elif req.startswith("/fetch/view/"):
            keys = req[12:]
            p0 = keys.index('/')
            dmail_addr_enc = keys[:p0]
            dmail_key_enc = keys[p0+1:]

            dmail_addr = mbase32.decode(dmail_addr_enc)
            dmail_key = mbase32.decode(dmail_key_enc)

            dm = yield from _load_dmail(handler, dmail_key)

            if dm:
                valid_sig = dm.sender_valid
            else:
                dm, valid_sig =\
                    yield from _fetch_dmail(handler, dmail_addr, dmail_key)

            dmail_text = _format_dmail(dm, valid_sig)

            handler._send_content(\
                dmail_text.encode(), content_type="text/plain")
        elif req.startswith("/fetch/panel/mark_as_read/"):
            req_data = req[26:]

            p0 = req_data.index('/')
            dmail_key_enc = req_data[p0+1:]
            dmail_key = mbase32.decode(dmail_key_enc)

            def processor(dmail):
                dmail.read = not dmail.read
                return True

            yield from _process_dmail_message(handler, dmail_key, processor)

            handler._send_204()
        elif req.startswith("/fetch/panel/trash/"):
            req_data = req[20:]

            p0 = req_data.index('/')
            dmail_key_enc = req_data[p0+1:]
            dmail_key = mbase32.decode(dmail_key_enc)

            def processor(dmail):
                dmail.hidden = not dmail.hidden
                return True

            yield from _process_dmail_message(handler, dmail_key, processor)

            handler._send_204()
        elif req.startswith("/fetch/panel/"):
            req_data = req[13:]

            content = pages.dmail_fetch_panel_content[0].replace(\
                b"${DMAIL_IDS}", req_data.encode())

            handler._send_content([content, None])
        elif req.startswith("/fetch/wrapper/"):
            req_data = req[15:]

            content = pages.dmail_fetch_wrapper[0].replace(\
                b"${IFRAME_SRC}",\
                "../../view/{}"\
                    .format(req_data).encode())
            #FIXME: This is getting inefficient now, maybe time for Flask or
            # something like it. Maybe we can use just it's template renderer.
            content = content.replace(\
                b"${IFRAME2_SRC}",\
                "../../panel/{}"\
                    .format(req_data).encode())

            handler._send_content([content, None])
        elif req.startswith("/fetch/"):
            req_data = req[7:]

            content = pages.dmail_address_page_content[0].replace(\
                b"${IFRAME_SRC}", "../wrapper/{}".format(req_data).encode())

            handler._send_content([content, None])
        elif req == "/create_address":
            handler._send_content(pages.dmail_create_address_content)
        elif req == "/create_address/form":
            handler._send_content(pages.dmail_create_address_form_content)
        elif req.startswith("/create_address/make_it_so?"):
            query = req[27:]

            qdict = urllib.parse.parse_qs(query)

            prefix = qdict["prefix"][0]
            difficulty = int(qdict["difficulty"][0])

            log.info("prefix=[{}].".format(prefix))
            privkey, dmail_key, dms =\
                yield from _create_dmail_address(handler, prefix, difficulty)

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

    req = rpath[len(s_dmail):]

    if req == "/compose/make_it_so":
        data = handler.rfile.read(int(handler.headers["Content-Length"]))

        if log.isEnabledFor(logging.DEBUG):
            log.debug("data=[{}].".format(data))

        dd = urllib.parse.parse_qs(data)

        if log.isEnabledFor(logging.DEBUG):
            log.debug("dd=[{}].".format(dd))

        subject = dd.get(b"subject")
        if subject:
            subject = subject[0].decode()
        else:
            subject = ""

        sender_dmail_id = dd.get(b"sender")

        if sender_dmail_id:
            sender_dmail_id = int(sender_dmail_id[0])

            if log.isEnabledFor(logging.DEBUG):
                log.debug("sender_dmail_id=[{}].".format(sender_dmail_id))

            dmail_address =\
                yield from _fetch_dmail_address(handler, sender_dmail_id)

            sender_asymkey = rsakey.RsaKey(\
                privdata=dmail_address.site_privatekey)\
                    if dmail_address else None
        else:
            sender_asymkey = None

        dest_addr_enc = dd.get(b"destination")
        if not dest_addr_enc:
            handler._send_error("You must specify a destination.", 400)
            return

        recipient, significant_bits =\
            mutil.decode_key(dest_addr_enc[0].decode())
        recipients = [(dest_addr_enc, bytes(recipient), significant_bits)]

        content = dd.get(b"content")
        if content:
            content = content[0]

        de =\
            dmail.DmailEngine(handler.node.chord_engine.tasks, handler.node.db)

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

@asyncio.coroutine
def _fetch_dmail_address(handler, dmail_address_id):
    "Fetch from our database the parameters that are stored in a DMail site."

    def dbcall():
        with handler.node.db.open_session() as sess:
            q = sess.query(DmailAddress)\
                .filter(DmailAddress.id == dmail_address_id)

            dmailaddr = q.first()

            if not dmailaddr:
                return None

            sess.expunge(dmailaddr)

            return dmailaddr

    dmailaddr = yield from handler.node.loop.run_in_executor(None, dbcall)

    return dmailaddr

@asyncio.coroutine
def _list_dmail_addresses(handler):
    def dbcall():
        with handler.node.db.open_session() as sess:
            q = sess.query(DmailAddress)

            log.info("Fetching addresses...")

            site_keys = []

            for addr in mutil.page_query(q):
                site_keys.append((addr.id, addr.site_key))

            sess.rollback()

            return site_keys

    site_keys = yield from handler.node.loop.run_in_executor(None, dbcall)

    return site_keys

@asyncio.coroutine
def _list_dmails_for_tag(handler, addr, tag):
    def dbcall():
        with handler.node.db.open_session() as sess:
            q = sess.query(DmailMessage)\
                .filter(\
                    DmailMessage.address.has(DmailAddress.site_key == addr))\
                .filter(DmailMessage.tags.any(DmailTag.name == tag))\
                .filter(DmailMessage.hidden == False)\
                .order_by(DmailMessage.read, DmailMessage.date.desc())

            msgs = q.all()

            sess.expunge_all()

            return msgs

    msgs = yield from handler.node.loop.run_in_executor(None, dbcall)

    addr_enc = mbase32.encode(addr)

    for msg in msgs:
        key_enc = mbase32.encode(msg.data_key)

        is_read = "" if msg.read else "(unread)"

        subject = msg.subject
        if len(subject) > 80:
            subject = subject[:80] + "..."

        sender_key = msg.sender_dmail_key
        if sender_key:
            if msg.sender_valid:
                sender_key = mbase32.encode(sender_key[:32]) + "..."
            else:
                sender_key = """<span class="strikethrough">""" + mbase32.encode(sender_key[:32]) + "</span>..."
        else:
            sender_key = "Anonymous"

        handler._send_partial_content(\
            """<span class="nowrap">{}: <a href="../../../../fetch/{}/{}" title="{}">{}</a>&nbsp;-&nbsp;{}</span><span class="right_text tag">{}</span><br/>"""\
                .format(\
                    mutil.format_human_no_ms_datetime(msg.date),\
                    addr_enc,\
                    key_enc,\
#                    key_enc[:32],\
                    key_enc,
                    subject,\
                    sender_key,\
                    is_read))

    if not msgs:
        handler._send_partial_content("Mailbox is empty.")

@asyncio.coroutine
def _scan_new_dmails(handler, addr, significant_bits):
    de =\
        dmail.DmailEngine(handler.node.chord_engine.tasks, handler.node.db)

    new_dmail_cnt = 0

    @asyncio.coroutine
    def process_key(key):
        nonlocal new_dmail_cnt

        exists = yield from _check_have_dmail(handler, key)

        key_enc = mbase32.encode(key)

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Processing Dmail (key=[{}]).".format(key_enc))

        if exists:
            if log.isEnabledFor(logging.DEBUG):
                log.debug("Ignoring dmail (key=[{}]) we already have."\
                    .format(key_enc))
            return

        yield from _fetch_and_save_dmail(handler, addr, key)

        addr_enc = mbase32.encode(addr)
        handler._send_partial_content(\
            """<a href="../../fetch/{}/{}">{}</a><br/>"""\
                .format(addr_enc, key_enc, key_enc))

        new_dmail_cnt += 1

    tasks = []

    def key_callback(key):
        tasks.append(asyncio.async(process_key(key), loop=handler.node.loop))

    try:
        yield from de.scan_dmail_address(\
            addr, significant_bits, key_callback=key_callback)
    except dmail.DmailException as e:
        handler._send_partial_content("DmailException: {}".format(e))

    if tasks:
        yield from asyncio.wait(tasks, loop=handler.node.loop)

    if new_dmail_cnt:
        handler._send_partial_content("Moved {} Dmails to Inbox."\
            .format(new_dmail_cnt))
    else:
        handler._send_partial_content("No new Dmails.")

@asyncio.coroutine
def _check_have_dmail(handler, dmail_key):
    def dbcall():
        with handler.node.db.open_session() as sess:
            q = sess.query(func.count("*"))\
                .filter(DmailMessage.data_key == dmail_key)

            if q.scalar():
                return True
            return False

    exists = yield from handler.node.loop.run_in_executor(None, dbcall)
    return exists

@asyncio.coroutine
def _fetch_and_save_dmail(handler, dmail_addr, dmail_key):
    dmailobj, valid_sig =\
        yield from _fetch_dmail(handler, dmail_addr, dmail_key)

    if not dmailobj:
        if log.isEnabledFor(logging.INFO):
            log.info("Dmail was not found on the network.")
        return

    def dbcall():
        with handler.node.db.open_session() as sess:
            handler.node.db.lock_table(sess, DmailMessage)

            q = sess.query(func.count("*"))\
                .filter(DmailMessage.data_key == dmail_key)

            if q.scalar():
                return False

            q = sess.query(DmailAddress.id)\
                .filter(DmailAddress.site_key == dmail_addr)

            dmail_address = q.first()

            msg = DmailMessage()
            msg.dmail_address_id = dmail_address.id
            msg.data_key = dmail_key
            msg.sender_dmail_key =\
                enc.generate_ID(dmailobj.sender_pubkey)\
                    if dmailobj.sender_pubkey else None
            msg.sender_valid = valid_sig
            msg.subject = dmailobj.subject
            msg.date = mutil.parse_iso_datetime(dmailobj.date)

            msg.hidden = False
            msg.read = False

            tag = DmailTag()
            tag.name = "Inbox"
            msg.tags = [tag]

            msg.parts = []

            for part in dmailobj.parts:
                dbpart = DmailPart()
                dbpart.mime_type = part.mime_type
                dbpart.data = part.data
                msg.parts.append(dbpart)

            sess.add(msg)

            sess.commit()

    yield from handler.node.loop.run_in_executor(None, dbcall)

    if log.isEnabledFor(logging.INFO):
        log.info("Dmail saved!")

    return

@asyncio.coroutine
def _load_dmail(handler, dmail_key):
    def dbcall():
        with handler.node.db.open_session() as sess:
            q = sess.query(DmailMessage)\
                .options(joinedload("parts"))\
                .filter(DmailMessage.data_key == dmail_key)

            dmail = q.first()

            sess.expunge_all()

            return dmail

    dmail = yield from handler.node.loop.run_in_executor(None, dbcall)

    return dmail

@asyncio.coroutine
def _process_dmail_message(handler, dmail_key, process_call):
    def dbcall():
        with handler.node.db.open_session() as sess:
            q = sess.query(DmailMessage)\
                .filter(DmailMessage.data_key == dmail_key)

            dmail = q.first()

            if process_call(dmail):
                sess.commit()

            sess.expunge_all()

            return dmail

    dmail = yield from handler.node.loop.run_in_executor(None, dbcall)

    return dmail

@asyncio.coroutine
def _load_dmail_address(handler, dmail_addr):
    def dbcall():
        with handler.node.db.open_session() as sess:
            q = sess.query(DmailAddress)\
                .filter(DmailAddress.site_key == dmail_addr)

            dmail_address = q.first()

            keys = dmail_address.keys

            sess.expunge_all()

            return dmail_address

    dmail_address =\
        yield from handler.node.loop.run_in_executor(None, dbcall)

    return dmail_address

@asyncio.coroutine
def _process_dmail_address(handler, dmail_addr, process_call):
    def dbcall():
        with handler.node.db.open_session() as sess:
            q = sess.query(DmailAddress)\
                .filter(DmailAddress.site_key == dmail_addr)

            dmail_address = q.first()

            if process_call(dmail_address):
                sess.commit()

            keys = dmail_address.keys

            sess.expunge_all()

            return dmail_address

    dmail_address =\
        yield from handler.node.loop.run_in_executor(None, dbcall)

    return dmail_address

@asyncio.coroutine
def _fetch_dmail(handler, dmail_addr, dmail_key):
    de =\
        dmail.DmailEngine(handler.node.chord_engine.tasks, handler.node.db)

    if log.isEnabledFor(logging.INFO):
        dmail_key_enc = mbase32.encode(dmail_key)
        dmail_addr_enc = mbase32.encode(dmail_addr)
        log.info("Fetching dmail (key=[{}]) for address=[{}]."\
            .format(dmail_key_enc, dmail_addr_enc))

    dmail_address = yield from _load_dmail_address(handler, dmail_addr)

    dmail_key_obj = dmail_address.keys[0]

    target_key = dmail_key_obj.target_key
    x_bin = dmail_key_obj.x

    l, x = sshtype.parseMpint(x_bin)

    dm, valid_sig =\
        yield from de.fetch_dmail(bytes(dmail_key), x, target_key)

    if not dm:
        handler._send_partial_content(\
            "Dmail for key [{}] was not found."\
                .format(dmail_key_enc))
        return None, None

    return dm, valid_sig

def _format_dmail(dm, valid_sig):
    from_db = type(dm) is DmailMessage

    dmail_text = []

    if (from_db and dm.sender_dmail_key) or (not from_db and dm.sender_pubkey):
        if from_db:
            sender_dmail_key = dm.sender_dmail_key
        else:
            sender_dmail_key = enc.generate_ID(dm.sender_pubkey)

        if valid_sig:
            dmail_text += "Sender Address Verified.\n\n"
        else:
            dmail_text += "WARNING: Sender Address Forged!\n\n"

        dmail_text += "From: {}\n".format(mbase32.encode(sender_dmail_key))

    dmail_text += "Subject: {}\n".format(dm.subject)

    if from_db:
        date_fmtted = dm.date
    else:
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

    return dmail_text

@asyncio.coroutine
def _create_dmail_address(handler, prefix, difficulty):
    de = dmail.DmailEngine(handler.node.chord_engine.tasks, handler.node.db)
    privkey, data_key, dms =\
        yield from de.generate_dmail_address(prefix, difficulty)
    return privkey, data_key, dms
