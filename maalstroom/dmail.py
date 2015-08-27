# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
from datetime import datetime
import logging
import textwrap
import threading
import time
from urllib.parse import parse_qs, quote_plus

from sqlalchemy import func, not_
from sqlalchemy.orm import joinedload

import base58
import consts
from db import DmailAddress, DmailKey, DmailMessage, DmailTag, DmailPart,\
    NodeState
import dhgroup14
import enc
import dmail
import mbase32
import mutil
import maalstroom.templates as templates
import rsakey
import sshtype

log = logging.getLogger(__name__)

s_dmail = ".dmail"

@asyncio.coroutine
def serve_get(dispatcher, rpath):
    log.info("Service .dmail request.")

    req = rpath[len(s_dmail):]

#    if log.isEnabledFor(logging.INFO):
#        log.info("req=[{}].".format(req))

    if req == "" or req == "/" or req.startswith("/wrapper/"):
        if dispatcher.handle_cache(req):
            return

        if req.startswith("/wrapper/"):
            params = req[9:]

            pq = params.find('?')

            if pq != -1:
                qline = params[pq+1:]
                params = params[:pq]
            else:
                qline = None

            p0 = params.find('/')
            if p0 == -1:
                p0 = len(params)
                tag = "Inbox"
            else:
                tag = params[p0+1:]
            addr_enc = params[:p0]
        else:
            tag = "Inbox"
            addr_enc = ""
            qline = None

        msg_list = None
        if qline:
            eparams = parse_qs(qline)
            msg_list = eparams.get("msg_list")
            if msg_list:
                msg_list = msg_list[0]

        if not msg_list:
            msg_list = "morphis://.dmail/msg_list/" + addr_enc + '/' + tag

        template = templates.dmail_page_wrapper[0]
        template = template.format(\
            tag=tag, addr=addr_enc, msg_list_iframe_url=msg_list)

        dispatcher.send_content([template, req])
        return

    if req == "/style.css":
        dispatcher.send_content(templates.dmail_css, content_type="text/css")
    elif req == "/logo":
        template = templates.dmail_logo[0]

        current_version = dispatcher.node.morphis_version
        latest_version_number = dispatcher.latest_version_number

        if latest_version_number\
                and current_version != latest_version_number:
            version_str =\
                '<span class="strikethrough nomargin">{}</span>]'\
                '&nbsp;[<a href="{}{}">GET {}</a>'\
                    .format(current_version,\
                        dispatcher.handler.maalstroom_url_prefix_str,\
                        "sp1nara3xhndtgswh7fznt414we4mi3y6kdwbkz4jmt8ocb6"\
                            "x4w1faqjotjkcrefta11swe3h53dt6oru3r13t667pr7"\
                            "cpe3ocxeuma/latest_version",\
                        latest_version_number)
        else:
            version_str = current_version

        connections = dispatcher.connection_count
        if connections == 1:
            connection_str = "1 Connection"
        else:
            connection_str = str(connections) + " Connections"

        template = template.format(\
            version=version_str,\
            connections=connection_str)

        dispatcher.send_content(template)
    elif req.startswith("/nav/"):
        params = req[5:]

        p0 = params.index('/')

        addr_enc = params[:p0]
        tag = params[p0+1:]

        template = templates.dmail_nav[0]

        template = template.format(addr=addr_enc, tag=tag)

        dispatcher.send_content(template)
    elif req.startswith("/aside/"):
        params = req[7:]
        p0 = params.index('/')
        addr_enc = params[:p0]
        tag = params[p0+1:]

        if not addr_enc:
            dmail_address = yield from _load_default_dmail_address(dispatcher)
            if dmail_address:
                addr_enc = mbase32.encode(dmail_address.site_key)

        addr = mbase32.decode(addr_enc)

        template = templates.dmail_aside[0]

        top_tags = ["Inbox", "Outbox", "Sent", "Drafts", "Trash"]
        fmt = {}

        for top_tag in top_tags:
            active = top_tag == tag
            unread_count = yield from _count_unread_dmails(\
                dispatcher, addr, top_tag)

            fmt[top_tag + "_active"] = "active-mailbox" if active else ""
            fmt[top_tag + "_unread_count"] =\
                unread_count if unread_count else ""
            fmt[top_tag + "_unread_class"] =\
                ("active-notify" if active else "inactive-notify")\
                    if unread_count else ""

        template = template.format(addr=addr_enc, **fmt)

        dispatcher.send_content(template)
    elif req.startswith("/msg_list/list/"):
        params = req[15:]
        p0 = params.index('/')
        addr_enc = params[:p0]
        tag = params[p0+1:]

        acharset = dispatcher.get_accept_charset()
        dispatcher.send_partial_content(\
            templates.dmail_msg_list_list_start[0],\
            True,\
            content_type="text/html; charset={}".format(acharset))
        
        yield from _list_dmails_for_tag(dispatcher, addr_enc, tag)

        dispatcher.send_partial_content(templates.dmail_msg_list_list_end[0])
        dispatcher.end_partial_content()
    elif req.startswith("/msg_list/"):
        params = req[10:]
        p0 = params.index('/')
        addr_enc = params[:p0]
        tag = params[p0+1:]

        if not addr_enc:
            dmail_address = yield from _load_default_dmail_address(dispatcher)
            if dmail_address:
                addr_enc = mbase32.encode(dmail_address.site_key)
            cacheable = False
        else:
            if dispatcher.handle_cache(req):
                return
            cacheable = True

        template = templates.dmail_msg_list[0]
        template = template.format(tag=tag, addr=addr_enc)

        if cacheable:
            dispatcher.send_content(template, req)
        else:
            dispatcher.send_content(template)
    elif req == "/new_mail":
        template = templates.dmail_new_mail[0]

        unread_count = yield from _count_unread_dmails(dispatcher)

        template = template.format(unread_count=unread_count)

        dispatcher.send_content(template)

    elif req.startswith("/images/"):
        dispatcher.send_content(templates.imgs[req[8:]])

    elif req.startswith("/tag/view/list/"):
        params = req[15:]

        p0 = params.index('/')
        tag = params[:p0]
        addr_enc = params[p0+1:]

        if log.isEnabledFor(logging.INFO):
            log.info("Viewing dmails with tag [{}] for address [{}]."\
                .format(tag, addr_enc))

        start = templates.dmail_tag_view_list_start.replace(\
            b"${TAG_NAME}", tag.encode())
        #FIXME: This is getting inefficient now, maybe time for Flask or
        # something like it. Maybe we can use just it's template renderer.
        start = start.replace(b"${DMAIL_ADDRESS}", addr_enc.encode())
        start = start.replace(\
            b"${DMAIL_ADDRESS2}",\
            "{}...".format(addr_enc[:32]).encode())

        acharset = dispatcher.get_accept_charset()

        dispatcher.send_partial_content(\
            start,\
            True,\
            content_type="text/html; charset={}".format(acharset))

        yield from\
            _list_dmails_for_tag(dispatcher, mbase32.decode(addr_enc), tag)

        dispatcher.send_partial_content(templates.dmail_tag_view_list_end)
        dispatcher.end_partial_content()

    elif req.startswith("/read/content/"):
        params = req[14:]

        msg_dbid = params

        dm = yield from _load_dmail(dispatcher, msg_dbid)

        dmail_text = _format_dmail_content(dm)

        acharset = dispatcher.get_accept_charset()

        dispatcher.send_content(\
            dmail_text.encode(acharset),
            content_type="text/plain; charset={}".format(acharset))

    elif req.startswith("/read/subject/"):
        params = req[14:]

        msg_dbid = params

        dm = yield from _load_dmail(dispatcher, msg_dbid)

        acharset = dispatcher.get_accept_charset()

        dispatcher.send_content(\
            dm.subject.encode(acharset),
            content_type="text/plain; charset={}".format(acharset))

    elif req.startswith("/read/"):
        params = req[6:]

        p0 = params.index('/')
        p1 = params.index('/', p0+1)

        addr_enc = params[:p0]
        tag = params[p0+1:p1]
        msg_dbid = params[p1+1:]

        def processor(sess, dm):
            dm.read = True
            return True

        dm = yield from _process_dmail_message(\
            dispatcher, msg_dbid, processor, fetch_parts=True)

        if dm.hidden:
            trash_msg = "REMOVE FROM TRASH"
        else:
            trash_msg = "MOVE TO TRASH"

        reply_subject = dm.subject if dm.subject.startswith("Re: ")\
            else "Re: " + dm.subject
        safe_reply_subject = quote_plus(reply_subject)
        sender_addr = mbase32.encode(dm.sender_dmail_key)
        sender_class =\
            "valid_sender" if dm.sender_valid else "invalid_sender"

        template = templates.dmail_read[0]
        template = template.format(\
            addr=addr_enc,\
            tag=tag,\
            safe_reply_subject=safe_reply_subject,\
            trash_msg=trash_msg,\
            msg_id=msg_dbid,\
            sender_class=sender_class,\
            sender=sender_addr,\
            date=dm.date)

        dispatcher.send_content(template)
    elif req.startswith("/compose/"):
        if len(req) > 8 and req[8] == '/':
            params = req[9:]
        else:
            params = req[8:]

        p0 = params.find('?')
        if p0 != -1:
            eparams = parse_qs(params[p0+1:])

            subject = eparams.get("subject")
            if subject:
                subject = subject[0]
            else:
                subject = ""

            sender_addr_enc = eparams.get("sender")
            if sender_addr_enc:
                sender_addr_enc = sender_addr_enc[0]
            else:
                sender_addr_enc = ""

            message_text = eparams.get("message")
            if message_text:
                message_text = message_text[0]
            else:
                message_text = ""
        else:
            subject = ""
            sender_addr_enc = ""
            message_text = ""
            p0 = len(params)

        dest_addr_enc = params[:p0]

        autofocus_fields = {\
            "dest_addr_autofocus": "",\
            "subject_autofocus": "",\
            "message_text_autofocus": ""}
        if not dest_addr_enc:
            autofocus_fields["dest_addr_autofocus"] = " autofocus"
        elif not subject:
            autofocus_fields["subject_autofocus"] = " autofocus"
        elif not message_text:
            autofocus_fields["message_text_autofocus"] = " autofocus"

        addrs = yield from _list_dmail_addresses(dispatcher)

        if sender_addr_enc:
            sender_addr = mbase32.decode(sender_addr_enc)
            default_id = None
        else:
            sender_addr = None
            default_id = yield from _load_default_dmail_address_id(dispatcher)

        from_addr_options = []

        for addr in addrs:
            if sender_addr:
                selected = addr.site_key.startswith(sender_addr)
            elif default_id:
                selected = addr.id == default_id
            else:
                selected = False

            if selected:
                option = '<option value="{}" selected>{}</option>'
                owner_if_anon = addr
            else:
                option = '<option value="{}">{}</option>'

            addr_enc = mbase32.encode(addr.site_key)

            from_addr_options.append(option.format(addr.id, addr_enc))

        from_addr_options.append("<option value="">[Anonymous]</option>")

        from_addr_options = ''.join(from_addr_options)

        template = templates.dmail_compose[0]

        template = template.format(\
            delete_class="display_none",\
            owner_if_anon=owner_if_anon.id,\
            from_addr_options=from_addr_options,\
            dest_addr=dest_addr_enc,\
            subject=subject,\
            message_text=message_text,\
            **autofocus_fields)

        acharset = dispatcher.get_accept_charset()
        dispatcher.send_content(template,\
            content_type="text/html; charset={}".format(acharset))

    # Actions.

    elif req.startswith("/toggle_read/"):
        params = req[13:]
        p0 = params.find('?redirect=')
        if p0 != -1:
            redirect = params[p0+10:]
        else:
            redirect = None
            p0 = len(params)

        msg_dbid = params[:p0]

        def processor(sess, dm):
            dm.read = not dm.read
            return True

        yield from _process_dmail_message(dispatcher, msg_dbid, processor)

        if redirect:
            dispatcher.send_301(redirect)
        else:
            dispatcher.send_204()
    elif req.startswith("/toggle_trashed/"):
        params = req[16:]
        p0 = params.find('?redirect=')
        if p0 != -1:
            redirect = params[p0+10:]
        else:
            redirect = None
            p0 = len(params)

        msg_dbid = params[:p0]

        def processor(sess, dm):
            dm.hidden = not dm.hidden
            return True

        yield from _process_dmail_message(dispatcher, msg_dbid, processor)

        if redirect:
            dispatcher.send_301(redirect)
        else:
            dispatcher.send_204()
    elif req.startswith("/make_address_default/"):
        params = req[22:]
        p0 = params.find('?redirect=')
        if p0 != -1:
            redirect = params[p0+10:]
        else:
            redirect = None
            p0 = len(params)

        addr_dbid = params[:p0]

        yield from _set_default_dmail_address(dispatcher, addr_dbid)

        if redirect:
            dispatcher.send_301(redirect)
        else:
            dispatcher.send_204()

#######OLD:

    elif req == "/address_list":
        dispatcher.send_partial_content(
            templates.dmail_page_content__f1_start, True)

        addrs = yield from _list_dmail_addresses(dispatcher)

        default_id = yield from _load_default_dmail_address_id(dispatcher)

        for addr in addrs:
            site_key_enc = mbase32.encode(addr.site_key)

            if default_id and addr.id == default_id:
                hide = "hidden"
            else:
                hide = ""

            resp =\
                '<div style="overflow: hidden; text-overflow: ellipsis;">'\
                '[<a href="morphis://.dmail/wrapper/{addr}" class="normal">'\
                'select</a>]&nbsp<span class="{hide}">'\
                '[<a target="_self" href="morphis://.dmail/'\
                'make_address_default/{addr_dbid}?redirect=morphis://.dmail/'\
                'address_list" class="normal">set&nbsp;default</a>]</span>'\
                '&nbsp{addr}</div>'\
                    .format(addr=site_key_enc, addr_dbid=addr.id, hide=hide)

            dispatcher.send_partial_content(resp)

        dispatcher.send_partial_content(\
            templates.dmail_page_content__f1_end)
        dispatcher.end_partial_content()

#######OLD UNUSED (DELETE):

    elif req.startswith("/compose/form"):
        dest_addr_enc = req[14:] if len(req) > 14 else ""

        dispatcher.send_partial_content(\
            templates.dmail_compose_dmail_form_start, True)

        addrs = yield from _list_dmail_addresses(dispatcher)

        for addr in addrs:
            site_key_enc = mbase32.encode(addr.site_key)

            sender_element = """<option value="{}">{}</option>"""\
                .format(addr.id, site_key_enc)

            dispatcher.send_partial_content(sender_element)

        dispatcher.send_partial_content(\
            "<option value="">[Anonymous]</option>")

        dispatcher.send_partial_content(\
            templates.dmail_compose_dmail_form_end.replace(\
                b"${DEST_ADDR}", dest_addr_enc.encode()))

        dispatcher.end_partial_content()
    elif req.startswith("/compose"):
        from_addr = req[9:] if len(req) > 9 else ""

        if from_addr:
            iframe_src = "../compose/form/{}".format(from_addr).encode()
        else:
            iframe_src = "compose/form".encode()

        content = templates.dmail_compose_dmail_content[0].replace(\
                b"${IFRAME_SRC}", iframe_src)

        dispatcher.send_content([content, None])
    elif req.startswith("/addr/view/"):
        addr_enc = req[11:]

        start = templates.dmail_addr_view_start.replace(\
            b"${DMAIL_ADDRESS}", addr_enc.encode())
        start = start.replace(\
            b"${DMAIL_ADDRESS_SHORT}", addr_enc[:32].encode())

        dispatcher.send_partial_content(start, True)

        dispatcher.send_partial_content(templates.dmail_addr_view_end)
        dispatcher.end_partial_content()
    elif req.startswith("/addr/settings/edit/publish?"):
        query = req[28:]

        qdict = parse_qs(query, keep_blank_values=True)

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
                dispatcher, mbase32.decode(addr_enc), processor)

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

        total_storing = 0
        retry = 0
        while True:
            storing_nodes = yield from\
                dispatcher.node.chord_engine.tasks\
                    .send_store_updateable_key(\
                        dms.export(), private_key,\
                        version=int(time.time()*1000), store_key=True)

            total_storing += storing_nodes

            if total_storing >= 3:
                break

            if retry > 32:
                break
            elif retry > 3:
                yield from asyncio.sleep(1)

            retry += 1

        if storing_nodes:
            dispatcher.send_content(\
                templates.dmail_addr_settings_edit_success_content[0]\
                    .format(addr_enc, addr_enc[:32]).encode())
        else:
            dispatcher.send_content(\
                templates.dmail_addr_settings_edit_fail_content[0]\
                    .format(addr_enc, addr_enc[:32]).encode())

    elif req.startswith("/addr/settings/edit/"):
        addr_enc = req[20:]

        #FIXME: YOU_ARE_HERE: This uses id now, not addr_enc.
        dmail_address = yield from\
            _load_dmail_address(dispatcher, mbase32.decode(addr_enc))

        content = templates.dmail_addr_settings_edit_content[0].replace(\
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

        dispatcher.send_content([content, None])
    elif req.startswith("/addr/settings/"):
        addr_enc = req[15:]

        content = templates.dmail_addr_settings_content[0].replace(\
            b"${IFRAME_SRC}",\
            "edit/{}".format(addr_enc).encode())

        dispatcher.send_content([content, None])
    elif req.startswith("/addr/"):
        addr_enc = req[6:]

        if log.isEnabledFor(logging.INFO):
            log.info("Viewing dmail address [{}].".format(addr_enc))

        content = templates.dmail_address_page_content[0].replace(\
            b"${IFRAME_SRC}", "view/{}".format(addr_enc).encode())

        dispatcher.send_content([content, None])
    elif req.startswith("/tag/view/list/"):
        params = req[15:]

        p0 = params.index('/')
        tag = params[:p0]
        addr_enc = params[p0+1:]

        if log.isEnabledFor(logging.INFO):
            log.info("Viewing dmails with tag [{}] for address [{}]."\
                .format(tag, addr_enc))

        start = templates.dmail_tag_view_list_start.replace(\
            b"${TAG_NAME}", tag.encode())
        #FIXME: This is getting inefficient now, maybe time for Flask or
        # something like it. Maybe we can use just it's template renderer.
        start = start.replace(b"${DMAIL_ADDRESS}", addr_enc.encode())
        start = start.replace(\
            b"${DMAIL_ADDRESS2}",\
            "{}...".format(addr_enc[:32]).encode())

        acharset = dispatcher.get_accept_charset()

        dispatcher.send_partial_content(\
            start,\
            True,\
            content_type="text/html; charset={}".format(acharset))

        yield from\
            _list_dmails_for_tag(dispatcher, mbase32.decode(addr_enc), tag)

        dispatcher.send_partial_content(templates.dmail_tag_view_list_end)
        dispatcher.end_partial_content()

    elif req.startswith("/tag/view/"):
        params = req[10:]

        content = templates.dmail_tag_view_content[0].replace(\
            b"${IFRAME_SRC}", "../list/{}".format(params).encode())

        dispatcher.send_content(content)
    elif req.startswith("/scan/list/"):
        addr_enc = req[11:]

        if log.isEnabledFor(logging.INFO):
            log.info("Viewing inbox for dmail address [{}]."\
                .format(addr_enc))

        start = templates.dmail_inbox_start.replace(\
            b"${DMAIL_ADDRESS}", addr_enc.encode())
        start = start.replace(\
            b"${DMAIL_ADDRESS2}", "{}...".format(addr_enc[:32]).encode())

        dispatcher.send_partial_content(start, True)

        addr, significant_bits = mutil.decode_key(addr_enc)

        yield from _scan_new_dmails(dispatcher, addr, significant_bits)

        dispatcher.send_partial_content(templates.dmail_inbox_end)
        dispatcher.end_partial_content()
    elif req.startswith("/scan/"):
        addr_enc = req[6:]

        content = templates.dmail_address_page_content[0].replace(\
            b"${IFRAME_SRC}", "list/{}".format(addr_enc).encode())

        dispatcher.send_content([content, None])
    elif req.startswith("/fetch/view/"):
        keys = req[12:]
        p0 = keys.index('/')
        dmail_addr_enc = keys[:p0]
        dmail_key_enc = keys[p0+1:]

        dmail_addr = mbase32.decode(dmail_addr_enc)
        dmail_key = mbase32.decode(dmail_key_enc)

        dm = yield from _load_dmail(dispatcher, dmail_key)

        if dm:
            valid_sig = dm.sender_valid
        else:
            dm, valid_sig =\
                yield from _fetch_dmail(dispatcher, dmail_addr, dmail_key)

        dmail_text = _format_dmail(dm, valid_sig)

        acharset = dispatcher.get_accept_charset()

        dispatcher.send_content(\
            dmail_text.encode(acharset),
            content_type="text/plain; charset={}".format(acharset))
    elif req.startswith("/fetch/panel/mark_as_read/"):
        req_data = req[26:]

        p0 = req_data.index('/')
        dmail_key_enc = req_data[p0+1:]
        dmail_key = mbase32.decode(dmail_key_enc)

        def processor(sess, dm):
            dm.read = not dm.read
            return True

        yield from _process_dmail_message(dispatcher, dmail_key, processor)

        dispatcher.send_204()
    elif req.startswith("/fetch/panel/trash/"):
        req_data = req[20:]

        p0 = req_data.index('/')
        dmail_key_enc = req_data[p0+1:]
        dmail_key = mbase32.decode(dmail_key_enc)

        def processor(sess, dm):
            dm.hidden = not dm.hidden
            return True

        yield from _process_dmail_message(dispatcher, dmail_key, processor)

        dispatcher.send_204()
    elif req.startswith("/fetch/panel/"):
        req_data = req[13:]

        content = templates.dmail_fetch_panel_content[0].replace(\
            b"${DMAIL_IDS}", req_data.encode())

        dispatcher.send_content([content, None])
    elif req.startswith("/fetch/wrapper/"):
        req_data = req[15:]

        content = templates.dmail_fetch_wrapper[0].replace(\
            b"${IFRAME_SRC}",\
            "../../view/{}"\
                .format(req_data).encode())
        #FIXME: This is getting inefficient now, maybe time for Flask or
        # something like it. Maybe we can use just it's template renderer.
        content = content.replace(\
            b"${IFRAME2_SRC}",\
            "../../panel/{}"\
                .format(req_data).encode())

        dispatcher.send_content([content, None])
    elif req.startswith("/fetch/"):
        req_data = req[7:]

        content = templates.dmail_address_page_content[0].replace(\
            b"${IFRAME_SRC}", "../wrapper/{}".format(req_data).encode())

        dispatcher.send_content([content, None])
    elif req == "/create_address":
        dispatcher.send_content(templates.dmail_create_address_content)
    elif req == "/create_address/form":
        dispatcher.send_content(templates.dmail_create_address_form_content)
    elif req.startswith("/create_address/make_it_so?"):
        query = req[27:]

        qdict = parse_qs(query, keep_blank_values=True)

        prefix = qdict["prefix"][0]
        difficulty = int(qdict["difficulty"][0])

        log.info("prefix=[{}].".format(prefix))
        privkey, dmail_key, dms, storing_nodes =\
            yield from\
                _create_dmail_address(dispatcher, prefix, difficulty)

        dmail_key_enc = mbase32.encode(dmail_key)

        dispatcher.send_partial_content(templates.dmail_frame_start, True)
        if storing_nodes:
            dispatcher.send_partial_content(b"SUCCESS<br/>")
        else:
            dispatcher.send_partial_content(
                "PARTIAL SUCCESS<br/>"\
                "<p>Your Dmail site was generated successfully; however,"\
                " it failed to be stored on the network. To remedy this,"\
                " simply go to your Dmail address page and click the"\
                " [<a href=\"morphis://.dmail/addr/settings/{}\">Address"\
                " Settings</a>] link, and then click the \"Republish"\
                " Dmail Site\" button.</p>"\
                    .format(dmail_key_enc).encode())

        dispatcher.send_partial_content(\
            """<p>New dmail address: <a href="../addr/{}">{}</a></p>"""\
                .format(dmail_key_enc, dmail_key_enc).encode())
        dispatcher.send_partial_content(templates.dmail_frame_end)
        dispatcher.end_partial_content()
    else:
        dispatcher.send_error(errcode=400)

@asyncio.coroutine
def serve_post(dispatcher, rpath):
    assert rpath.startswith(s_dmail)

    req = rpath[len(s_dmail):]

    if req == "/compose/make_it_so":
        data = yield from dispatcher.read_request()

        if log.isEnabledFor(logging.DEBUG):
            log.debug("data=[{}].".format(data))

        dm = yield from _read_dmail_post(dispatcher, data)

        de =\
            dmail.DmailEngine(\
                dispatcher.node.chord_engine.tasks, dispatcher.node.db)

        dm = yield from _save_outgoing_dmail(dispatcher, dm, "Outbox")

        sender_asymkey =\
            rsakey.RsaKey(privdata=dm.address.site_privatekey) if dm.address\
                else None

        dest_addr_enc = mbase32.encode(dm.destination_dmail_key)
        destinations = [
            (dest_addr_enc,\
                dm.destination_dmail_key,\
                dm.destination_significant_bits)]

        storing_nodes =\
            yield from de.send_dmail(\
                sender_asymkey,\
                destinations,\
                dm.subject,\
                dm.date,\
                dm.parts[0].data)

        if not storing_nodes:
            dispatcher.send_content(\
                "FAIL.<br/><p>Dmail timed out being stored on the network;"\
                    " message remains in outbox.</p>"\
                        .format(dest_addr_enc).encode())

        dispatcher.send_content(\
            "SUCCESS.<br/><p>Dmail successfully sent to: {}</p>"\
                .format(dest_addr_enc).encode())

        def processor(sess, dm):
            log.info("Moving sent Dmail from Outbox to Sent.")
            remove_target = None
            for tag in dm.tags:
                if tag.name == "Outbox":
                    remove_target = tag
                    break
            dm.tags.remove(remove_target)
            dmail.attach_dmail_tag(sess, dm, "Sent")
            return True

        yield from _process_dmail_message(dispatcher, dm.id, processor)
    else:
        dispatcher.send_error(errcode=400)

@asyncio.coroutine
def _read_dmail_post(dispatcher, data):
    charset = dispatcher.handler.headers["Content-Type"]
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

    qs = data.decode(charset)
    dd = parse_qs(qs, keep_blank_values=True)

    if log.isEnabledFor(logging.DEBUG):
        log.debug("dd=[{}].".format(dd))

    dm = DmailMessage()

    subject = dd.get("subject")
    if subject:
        dm.subject = subject[0]
    else:
        dmsubject = ""

    sender_dmail_id = dd.get("sender")
    if sender_dmail_id:
        sender_dmail_id = sender_dmail_id[0]

        if log.isEnabledFor(logging.DEBUG):
            log.debug("sender_dmail_id=[{}].".format(sender_dmail_id))

        if sender_dmail_id and sender_dmail_id != "":
            sender_dmail_id = int(sender_dmail_id)

            dmail_address =\
                yield from _load_dmail_address(dispatcher, sender_dmail_id)

            dm.address = dmail_address
            dm.sender_valid = True

            dm.sender_dmail_key = dm.address.site_key

    if not dm.address:
        owner_if_anon = dd.get("owner_if_anon")
        if owner_if_anon:
            dmail_address =\
                yield from _load_dmail_address(dispatcher, owner_if_anon[0])
            dm.address = dmail_address

        if dm.address:
            dm.sender_valid = True
        else:
            dm.sender_valid = False

#        sender_asymkey = rsakey.RsaKey(\
#            privdata=dmail_address.site_privatekey)\
#                if dmail_address else None
#    else:
#        sender_asymkey = None

    dest_addr_enc = dd.get("destination")
    if dest_addr_enc:
        dm.destination_dmail_key, dm.destination_significant_bits =\
            mutil.decode_key(dest_addr_enc[0])
#            mbase32.decode(dest_addr_enc[0])

#   dispatcher.send_error("You must specify a destination.", 400)

    content = dd.get("content")
    if content:
        dp = DmailPart()
        dp.mime_type = "text/plain"
        dp.data = content[0].encode()
        dm.parts.append(dp)

    dm.date = datetime.today()

    dm.hidden = False
    dm.read = True

    return dm

@asyncio.coroutine
def _save_outgoing_dmail(dispatcher, dm, tag_name):
    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            dispatcher.node.db.lock_table(sess, DmailMessage)

            if dm.data_key:
                q = sess.query(func.count("*")).select_from(DmailMessage)\
                    .filter(DmailMessage.data_key == dm.data_key)

                if q.scalar():
                    log.warning(\
                        "Not saving dmail we already have saved,"\
                        " data_key=[{}]."\
                            .format(dmail_key))
                    return None
            else:
                # Local only message, as we haven't sent it yet.
                dm.data_key = b""

            dmail.attach_dmail_tag(sess, dm, tag_name)

            sess.add(dm)

            sess.expire_on_commit = False
            sess.commit()

            return dm

    dm = yield from dispatcher.node.loop.run_in_executor(None, dbcall)

    if log.isEnabledFor(logging.INFO):
        log.info("Dmail (id=[{}]) saved with tag [{}]!".format(dm, tag_name))

    return dm

@asyncio.coroutine
def _load_dmail_address(dispatcher, dmail_address_id):
    "Fetch from our database the parameters that are stored in a DMail site."

    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            q = sess.query(DmailAddress)\
                .options(joinedload("keys"))\
                .filter(DmailAddress.id == dmail_address_id)

            dmailaddr = q.first()

            if not dmailaddr:
                return None

            sess.expunge(dmailaddr)

            return dmailaddr

    dmailaddr = yield from dispatcher.loop.run_in_executor(None, dbcall)

    return dmailaddr

@asyncio.coroutine
def _load_default_dmail_address_id(dispatcher):
    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            q = sess.query(NodeState)\
                .filter(NodeState.key == consts.NSK_DEFAULT_ADDRESS)

            ns = q.first()

            if not ns:
                return None

            try:
                return int(ns.value)
            except ValueError:
                return None

    return dispatcher.loop.run_in_executor(None, dbcall)

@asyncio.coroutine
def _load_default_dmail_address(dispatcher):
    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            q = sess.query(NodeState)\
                .filter(NodeState.key == consts.NSK_DEFAULT_ADDRESS)

            ns = q.first()

            if ns:
                addr = sess.query(DmailAddress)\
                    .filter(DmailAddress.id == int(ns.value))\
                    .first()

                if addr:
                    sess.expunge(addr)
                    return addr

            addr = sess.query(DmailAddress)\
                .order_by(DmailAddress.id)\
                .limit(1)\
                .first()

            sess.expire_on_commit = False

            ns = NodeState()
            ns.key = consts.NSK_DEFAULT_ADDRESS
            ns.value = str(addr.id)
            sess.add(ns)
            sess.commit()

            sess.expunge(addr)
            return addr

    addr = yield from dispatcher.loop.run_in_executor(None, dbcall)

    return addr

@asyncio.coroutine
def _list_dmail_addresses(dispatcher):
    def dbcall():
        with dispatcher.node.db.open_session(True) as sess:
            log.info("Fetching addresses...")

            q = sess.query(DmailAddress).order_by(DmailAddress.id)

            return q.all()

    addrs = yield from dispatcher.loop.run_in_executor(None, dbcall)

    return addrs

@asyncio.coroutine
def _count_unread_dmails(dispatcher, addr=None, tag=None):
    if addr and type(addr) not in (bytes, bytearray):
        addr = mbase32.decode(addr)

    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            q = sess.query(func.count("*"))

            q = q.filter(DmailMessage.read == False)

            if addr:
                q = q.filter(\
                    DmailMessage.address.has(DmailAddress.site_key == addr))

            if tag == "Trash":
                q = q.filter(DmailMessage.hidden == True)
                return q.scalar()

            if tag:
                q = q.filter(DmailMessage.tags.any(DmailTag.name == tag))
            q = q.filter(DmailMessage.hidden == False)

            return q.scalar()

    cnt = yield from dispatcher.node.loop.run_in_executor(None, dbcall)

    return cnt

@asyncio.coroutine
def _load_dmails_for_tag(dispatcher, addr, tag):
    if type(addr) not in (bytes, bytearray):
        addr = mbase32.decode(addr)

    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            q = sess.query(DmailMessage)\
                .filter(\
                    DmailMessage.address.has(DmailAddress.site_key == addr))

            if tag == "Trash":
                q = q.filter(DmailMessage.hidden == True)
            else:
                q = q.filter(DmailMessage.tags.any(DmailTag.name == tag))\
                    .filter(DmailMessage.hidden == False)

            q = q.order_by(DmailMessage.read, DmailMessage.date.desc())

            msgs = q.all()

            sess.expunge_all()

            return msgs

    msgs = yield from dispatcher.node.loop.run_in_executor(None, dbcall)

    return msgs

@asyncio.coroutine
def _list_dmails_for_tag(dispatcher, addr, tag):
    msgs = yield from _load_dmails_for_tag(dispatcher, addr, tag)

    if type(addr) is str:
        addr_enc = addr
    else:
        addr_enc = mbase32.decode(addr)

    if not msgs:
        dispatcher.send_partial_content(\
            '<tr><td colspan="6">No messages.</td><tr></table>')
        return

    row_template = templates.dmail_msg_list_list_row[0]

    for msg in msgs:
        unread = "" if msg.read else "new-mail"

        mail_icon = "new-mail-icon" if unread else "mail-icon"

        subject = msg.subject
        if not subject:
            subject = "[no subject]"

        sender_key = msg.sender_dmail_key
        if sender_key:
            sender_key_enc = mbase32.encode(sender_key)
            if msg.sender_valid:
                sender_key = sender_key_enc
            else:
                sender_key = '<span class="strikethrough">'\
                    + sender_key_enc + "</span>"
        else:
            sender_key = "[Anonymous]"

        row = row_template.format(
            mail_icon=mail_icon,\
            tag=tag,\
            unread=unread,\
            addr=addr_enc,\
            msg_id=msg.id,\
            subject=subject,\
            sender=sender_key,\
            timestamp=msg.date)

        dispatcher.send_partial_content(row)

@asyncio.coroutine
def _scan_new_dmails(dispatcher, addr, significant_bits):
    de =\
        dmail.DmailEngine(\
            dispatcher.node.chord_engine.tasks, dispatcher.node.db)

    new_dmail_cnt = 0

    @asyncio.coroutine
    def process_key(key):
        nonlocal new_dmail_cnt

        exists = yield from _check_have_dmail(dispatcher, key)

        key_enc = mbase32.encode(key)

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Processing Dmail (key=[{}]).".format(key_enc))

        if exists:
            if log.isEnabledFor(logging.DEBUG):
                log.debug("Ignoring dmail (key=[{}]) we already have."\
                    .format(key_enc))
            return

        yield from _fetch_and_save_dmail(dispatcher, addr, key)

        addr_enc = mbase32.encode(addr)
        dispatcher.send_partial_content(\
            """<a href="../../fetch/{}/{}">{}</a><br/>"""\
                .format(addr_enc, key_enc, key_enc))

        new_dmail_cnt += 1

    tasks = []

    def key_callback(key):
        tasks.append(\
            asyncio.async(process_key(key), loop=dispatcher.node.loop))

    try:
        yield from de.scan_dmail_address(\
            addr, significant_bits, key_callback=key_callback)
    except dmail.DmailException as e:
        dispatcher.send_partial_content("DmailException: {}".format(e))

    if tasks:
        yield from asyncio.wait(tasks, loop=dispatcher.node.loop)

    if new_dmail_cnt:
        dispatcher.send_partial_content("Moved {} Dmails to Inbox."\
            .format(new_dmail_cnt))
    else:
        dispatcher.send_partial_content("No new Dmails.")

@asyncio.coroutine
def _check_have_dmail(dispatcher, dmail_key):
    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            q = sess.query(func.count("*")).select_from(DmailMessage)\
                .filter(DmailMessage.data_key == dmail_key)

            if q.scalar():
                return True
            return False

    exists = yield from dispatcher.node.loop.run_in_executor(None, dbcall)
    return exists

@asyncio.coroutine
def _fetch_and_save_dmail(dispatcher, dmail_addr, dmail_key):
    dmailobj, valid_sig =\
        yield from _fetch_dmail(dispatcher, dmail_addr, dmail_key)

    if not dmailobj:
        if log.isEnabledFor(logging.INFO):
            log.info("Dmail was not found on the network.")
        return

    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            dispatcher.node.db.lock_table(sess, DmailMessage)

            q = sess.query(func.count("*")).select_from(DmailMessage)\
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

    yield from dispatcher.node.loop.run_in_executor(None, dbcall)

    if log.isEnabledFor(logging.INFO):
        log.info("Dmail saved!")

    return

@asyncio.coroutine
def _load_dmail(dispatcher, dmail_dbid):
    def dbcall():
        with dispatcher.node.db.open_session(True) as sess:
            q = sess.query(DmailMessage)\
                .options(joinedload("parts"))\
                .filter(DmailMessage.id == dmail_dbid)

            dm = q.first()

            sess.expunge_all()

            return dm

    dm = yield from dispatcher.node.loop.run_in_executor(None, dbcall)

    return dm

@asyncio.coroutine
def _process_dmail_message(dispatcher, msg_dbid, process_call,\
        fetch_parts=False):
    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            sess.expire_on_commit = False

            q = sess.query(DmailMessage)
            if fetch_parts:
                q = q.options(joinedload("parts"))
            q = q.filter(DmailMessage.id == msg_dbid)

            dm = q.first()

            if process_call(sess, dm):
                sess.commit()

            sess.expunge_all()

            return dm

    dm = yield from dispatcher.node.loop.run_in_executor(None, dbcall)

    return dm

@asyncio.coroutine
def _set_default_dmail_address(dispatcher, dbid):
    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            q = sess.query(NodeState)\
                .filter(NodeState.key == consts.NSK_DEFAULT_ADDRESS)

            ns = q.first()

            if not ns:
                ns = NodeState()
                ns.key = consts.NSK_DEFAULT_ADDRESS
                sess.add(ns)

            if type(dbid) is int:
                sbid = str(dbid)

            ns.value = dbid

            sess.commit()

    yield from dispatcher.loop.run_in_executor(None, dbcall)

@asyncio.coroutine
#def _load_dmail_address(dispatcher, dmail_addr):
#    def dbcall():
#        with dispatcher.node.db.open_session() as sess:
#            q = sess.query(DmailAddress)\
#                .filter(DmailAddress.site_key == dmail_addr)
#
#            dmail_address = q.first()
#
#            keys = dmail_address.keys
#
#            sess.expunge_all()
#
#            return dmail_address
#
#    dmail_address =\
#        yield from dispatcher.node.loop.run_in_executor(None, dbcall)
#
#    return dmail_address

@asyncio.coroutine
def _process_dmail_address(dispatcher, dmail_addr, process_call):
    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            sess.expire_on_commit = False

            q = sess.query(DmailAddress)\
                .filter(DmailAddress.site_key == dmail_addr)

            dmail_address = q.first()

            if process_call(dmail_address):
                sess.commit()

            keys = dmail_address.keys

            sess.expunge_all()

            return dmail_address

    dmail_address =\
        yield from dispatcher.node.loop.run_in_executor(None, dbcall)

    return dmail_address

@asyncio.coroutine
def _fetch_dmail(dispatcher, dmail_addr, dmail_key):
    de =\
        dmail.DmailEngine(\
            dispatcher.node.chord_engine.tasks, dispatcher.node.db)

    if log.isEnabledFor(logging.INFO):
        dmail_key_enc = mbase32.encode(dmail_key)
        dmail_addr_enc = mbase32.encode(dmail_addr)
        log.info("Fetching dmail (key=[{}]) for address=[{}]."\
            .format(dmail_key_enc, dmail_addr_enc))

    #FIXME: YOU_ARE_HERE: This uses id now, not addr_enc.
    dmail_address = yield from _load_dmail_address(dispatcher, dmail_addr)

    dmail_key_obj = dmail_address.keys[0]

    target_key = dmail_key_obj.target_key
    x_bin = dmail_key_obj.x

    l, x = sshtype.parseMpint(x_bin)

    dm, valid_sig =\
        yield from de.fetch_dmail(bytes(dmail_key), x, target_key)

    if not dm:
        dispatcher.send_partial_content(\
            "Dmail for key [{}] was not found."\
                .format(dmail_key_enc))
        return None, None

    return dm, valid_sig

def _format_dmail_content(dm):
    assert type(dm) is DmailMessage

    dmail_text = []

    i = 0
    for part in dm.parts:
        dmail_text += part.data.decode()
        dmail_text += '\n'

        if len(dm.parts) > 1:
            dmail_text += "----- ^ dmail part #{} ^ -----\n\n".format(i)
            i += 1

    dmail_text = ''.join(dmail_text)

    dmail_text = wrap_long_lines(dmail_text)

    return dmail_text


def wrap_long_lines(text, limit=79):
    len_text = len(text)
    out = ""
    p0 = 0
    while p0 < len_text:
        p1 = text.find('\n', p0)
        if p1 == -1:
            p1 = len_text

        if (p1 - p0) <= limit:
            out += text[p0:p1+1]
            p0 = p1 + 1
            continue

        include_break_chr = False
        ps = text.rfind('-', p0, p0+limit)
        if ps == -1:
            ps = text.rfind(' ', p0, p0+limit)
            include_break_chr = True

        if ps == -1:
            out += text[p0:p0+limit]
            out += '\n'
            p0 += limit
            continue

        out += text[p0:ps]
        out += '\n'
        p0 = ps
        if not include_break_chr:
            p0 += 1

    return out

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
def _create_dmail_address(dispatcher, prefix, difficulty):
    de = dmail.DmailEngine(\
        dispatcher.node.chord_engine.tasks, dispatcher.node.db)
    privkey, data_key, dms, storing_nodes =\
        yield from de.generate_dmail_address(prefix, difficulty)
    return privkey, data_key, dms, storing_nodes
