# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
from datetime import datetime
import logging
import textwrap
import threading
import time
from urllib.parse import parse_qs, quote_plus, unquote

from sqlalchemy import func, not_, and_
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
top_tags = ["Inbox", "Outbox", "Sent", "Drafts", "Trash"]

@asyncio.coroutine
def serve_get(dispatcher, rpath):
    global top_tags

    log.info("Service .dmail request.")

    req = rpath[len(s_dmail):]

#    if log.isEnabledFor(logging.INFO):
#        log.info("req=[{}].".format(req))

    if req == "" or req == "/" or req == "/goto_new_mail"\
            or req.startswith("/wrapper/"):
        cacheable = False
        if req == "/goto_new_mail":
            tag = "Inbox"
            addr = yield from _load_first_address_with_new_mail(dispatcher)
            if addr:
                log.info("NEW")
                addr_enc = mbase32.encode(addr.site_key)
            else:
                log.info("NO NEW")
                addr_enc = ""
            qline = None
        elif req.startswith("/wrapper/"):
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

            if addr_enc:
                cacheable = True
                if dispatcher.handle_cache(req):
                    return
        else:
            tag = "Inbox"
            addr_enc = ""
            qline = None

        if not addr_enc:
            dmail_address = yield from _load_default_dmail_address(dispatcher)
            if dmail_address:
                addr_enc = mbase32.encode(dmail_address.site_key)

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

        if cacheable:
            dispatcher.send_content([template, req])
        else:
            dispatcher.send_content(template)
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

        template = template.format(\
            csrf_token=dispatcher.client_engine.csrf_token,\
            addr=addr_enc,\
            tag=tag)

        dispatcher.send_content(template)
    elif req.startswith("/aside/"):
        params = req[7:]
        p0 = params.index('/')
        addr_enc = params[:p0]
        tag = params[p0+1:]

        addr = mbase32.decode(addr_enc)

        template = templates.dmail_aside[0]

        fmt = {}

        for top_tag in top_tags:
            active = top_tag == tag
            unread_count =\
                yield from _count_unread_dmails(dispatcher, addr, top_tag)

            fmt[top_tag + "_active"] = "active-mailbox" if active else ""
            fmt[top_tag + "_unread_count"] =\
                unread_count if unread_count else ""
            fmt[top_tag + "_unread_class"] =\
                ("active-notify" if active else "inactive-notify")\
                    if unread_count else ""

        tags = yield from _load_tags(dispatcher, top_tags)

        tag_rows = []

        unquoted_tag = unquote(tag)

        for ctag in tags:
            if unquoted_tag == ctag.name:
                active = " active_tag"
            else:
                active = ""

            row = '<li class="bullet{active}"><span class="mailbox-pad">'\
                '<a href="morphis://.dmail/wrapper/{addr}/{tag}">{tag}</a>'\
                '</span></li>'\
                    .format(\
                        active=active,\
                        addr=addr_enc,\
                        tag=ctag.name)
            tag_rows.append(row)

        template = template.format(\
            csrf_token=dispatcher.client_engine.csrf_token,\
            addr=addr_enc,\
            tag=tag,\
            tag_rows=''.join(tag_rows),\
            **fmt)

        acharset = dispatcher.get_accept_charset()

        dispatcher.send_content(template)
    elif req.startswith("/msg_list/list/"):
        params = req[15:]
        p0 = params.index('/')
        addr_enc = params[:p0]
        tag = unquote(params[p0+1:])

        template = templates.dmail_msg_list_list_start[0]

        addr_heading = "TO" if tag in ("Outbox", "Sent", "Drafts") else "FROM"

        if tag == "Inbox" or tag == "":
            unread_check =\
                '<meta target="self" http-equiv="refresh" content="60"/>'
        else:
            unread_check = ""

        template = template.format(\
            unread_check=unread_check,\
            addr_heading=addr_heading)

        acharset = dispatcher.get_accept_charset()
        dispatcher.send_partial_content(\
            template,\
            True,\
            content_type="text/html; charset={}".format(acharset))
        
        yield from _list_dmails_for_tag(dispatcher, addr_enc, unquote(tag))

        dispatcher.send_partial_content(templates.dmail_msg_list_list_end[0])
        dispatcher.end_partial_content()
    elif req.startswith("/msg_list/"):
        params = req[10:]

        p0 = params.index('/')
        addr_enc = params[:p0]
        tag = params[p0+1:]

        if dispatcher.handle_cache(req):
            return

        if tag == "Trash":
            empty_trash_button_class = "link-button"
        else:
            empty_trash_button_class = "display_none"

        template = templates.dmail_msg_list[0]
        template = template.format(\
            csrf_token=dispatcher.client_engine.csrf_token,\
            tag=unquote(tag),\
            addr=addr_enc,\
            empty_trash_button_class=empty_trash_button_class)

        dispatcher.send_content([template, req])
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

        dm = yield from _load_dmail(dispatcher, msg_dbid, fetch_parts=True)

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
            dispatcher, msg_dbid, processor, fetch_parts=True, fetch_tags=True)

        if dm.hidden:
            trash_msg = "REMOVE FROM TRASH"
        else:
            trash_msg = "MOVE TO TRASH"

        m32_reply_subject = generate_safe_reply_subject(dm, True)

        if dm.sender_dmail_key:
            sender_addr = mbase32.encode(dm.sender_dmail_key)
            if dm.sender_valid:
                sender_class = "valid_sender"
            else:
                sender_class = "invalid_sender"
        else:
            sender_addr = "[Anonymous]"
            sender_class = "valid_sender"

        if dm.destination_dmail_key:
            dest_addr_enc = mbase32.encode(dm.destination_dmail_key)
            dest_class = ""
        else:
            dest_addr_enc = ""
            dest_class = " display_none"

        unquoted_tag = unquote(tag)

        existing_tag_rows = []
        if len(dm.tags) > 1:
            remove_tag_class = ""

            for etag in dm.tags:
                if etag.name == unquoted_tag:
                    selected = "selected "
                else:
                    selected = ""

                row = '<option {selected}value"{tag_id}">{tag_name}</option>'\
                    .format(\
                        selected=selected,\
                        tag_id=etag.id,\
                        tag_name=etag.name)
                existing_tag_rows.append(row)
        else:
            remove_tag_class = "display_none"

        current_tag_names = [x.name for x in dm.tags]
        current_tag_names.extend(top_tags)
        current_tag_names.remove("Inbox")
        tags = yield from _load_tags(dispatcher, current_tag_names)

        available_tag_rows = []

        for atag in tags:
            row = '<option value"{tag_id}">{tag_name}</option>'\
                .format(\
                    tag_id=atag.id,\
                    tag_name=atag.name)
            available_tag_rows.append(row)

        template = templates.dmail_read[0]
        template = template.format(\
            csrf_token=dispatcher.client_engine.csrf_token,\
            addr=addr_enc,\
            tag=tag,\
            m32_reply_subject=m32_reply_subject,\
            trash_msg=trash_msg,\
            msg_id=msg_dbid,\
            sender_class=sender_class,\
            sender=sender_addr,\
            dest_class=dest_class,\
            dest_addr=dest_addr_enc,\
            date=mutil.format_human_no_ms_datetime(dm.date),\
            remove_tag_class=remove_tag_class,\
            existing_tags=''.join(existing_tag_rows),\
            available_tags=''.join(available_tag_rows))

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
                subject = subject[0].replace('"', "&quot;")
            else:
                esubject = eparams.get("esubject")
                if esubject:
                    subject = mbase32.decode(esubject[0]).decode()
                    subject = subject.replace('"', "&quot;")
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
            if not default_id:
                owner_if_anon_id = ""

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
                owner_if_anon_id = addr.id
            else:
                option = '<option value="{}">{}</option>'

            addr_enc = mbase32.encode(addr.site_key)

            from_addr_options.append(option.format(addr.id, addr_enc))

        from_addr_options.append("<option value="">[Anonymous]</option>")

        from_addr_options = ''.join(from_addr_options)

        template = templates.dmail_compose[0]

        template = template.format(\
            csrf_token=dispatcher.client_engine.csrf_token,\
            delete_class="display_none",\
            owner_if_anon=owner_if_anon_id,\
            from_addr_options=from_addr_options,\
            dest_addr=dest_addr_enc,\
            subject=subject,\
            message_text=message_text,\
            **autofocus_fields)

        acharset = dispatcher.get_accept_charset()
        dispatcher.send_content(template,\
            content_type="text/html; charset={}".format(acharset))
    elif req == "/address_list":
        addrs = yield from _list_dmail_addresses(dispatcher)
        default_id = yield from _load_default_dmail_address_id(dispatcher)

        csrf_token = dispatcher.client_engine.csrf_token

        row_template = templates.dmail_address_list_row[0]

        rows = []

        for addr in addrs:
            site_key_enc = mbase32.encode(addr.site_key)

            if default_id and addr.id == default_id:
                set_default_class = "hidden"
            else:
                set_default_class = ""

            if addr.scan_interval:
                autoscan_link_text = "disable autoscan"
                autoscan_interval = 0
            else:
                autoscan_link_text = "enable autoscan"
                autoscan_interval = 60

            resp = row_template.format(\
                csrf_token=csrf_token,\
                addr=site_key_enc,\
                addr_dbid=addr.id,\
                set_default_class=set_default_class,\
                autoscan_link_text=autoscan_link_text,\
                autoscan_interval=autoscan_interval)

            rows.append(resp)

        rows_content = ''.join(rows)

        template = templates.dmail_address_list[0]
        template = template.format(address_list=rows_content)

        dispatcher.send_content(template)

    # Actions.

    elif req.startswith("/create_tag?"):
        query = req[12:]

        qdict = parse_qs(query, keep_blank_values=True)

        csrf_token = qdict["csrf_token"][0]

        if not dispatcher.check_csrf_token(csrf_token):
            return

        tag_name = qdict["tag_name"][0]

        if not tag_name:
            dispatcher.send_204()
            return

        r = yield from _create_tag(dispatcher, tag_name)

        redirect = qdict.get("redirect")
        if r and redirect:
            dispatcher.send_301(redirect[0])
        else:
            dispatcher.send_204()
    elif req.startswith("/modify_message_tag?"):
        query = req[20:]

        qdict = parse_qs(query, keep_blank_values=True)

        csrf_token = qdict["csrf_token"][0]

        if not dispatcher.check_csrf_token(csrf_token):
            return

        submit = qdict["submit"][0]

        def processor(sess, dm):
            if submit == "add_tag":
                dmail.attach_dmail_tag(sess, dm, qdict["add_tag"][0])
                return True
            elif submit == "move_to_tag":
                dm.tags.clear()
                dmail.attach_dmail_tag(sess, dm, qdict["add_tag"][0])
                return True
            elif submit == "remove_tag":
                if len(dm.tags) <= 1:
                    return False

                remove_tag = qdict["remove_tag"][0]
                remove_target = None
                for tag in dm.tags:
                    if tag.name == remove_tag:
                        remove_target = tag
                        break
                dm.tags.remove(remove_target)
                return True
            else:
                return False

        msg_id = qdict["msg_id"][0]

        dm = yield from _process_dmail_message(\
            dispatcher, msg_id, processor, fetch_tags=True)

        redirect = qdict.get("redirect")
        if redirect:
            dispatcher.send_301(redirect[0])
        else:
            dispatcher.send_204()
    elif req.startswith("/refresh/"):
        params = req[9:]

        p0 = params.index('/')

        csrf_token = params[:p0]
        addr_enc = params[p0+1:]

        if not dispatcher.check_csrf_token(csrf_token):
            return

        dmail_address = yield from _load_dmail_address(\
            dispatcher, site_key=mbase32.decode(addr_enc), fetch_keys=True)

        dispatcher.client_engine.trigger_dmail_scan(dmail_address)

        dispatcher.send_204()
    elif req.startswith("/toggle_read/"):
        params = req[13:]

        pq = params.find("?redirect=")
        if pq != -1:
            redirect = unquote(params[pq+10:])
        else:
            redirect = None
            pq = len(params)

        p0 = params.index('/', 0, pq)

        csrf_token = params[:p0]
        msg_dbid = params[p0+1:pq]

        if not dispatcher.check_csrf_token(csrf_token):
            return

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
        pq = params.find("?redirect=")
        if pq != -1:
            redirect = unquote(params[pq+10:])
        else:
            redirect = None
            pq = len(params)

        p0 = params.index('/', 0, pq)

        csrf_token = params[:p0]
        msg_dbid = params[p0+1:pq]

        if not dispatcher.check_csrf_token(csrf_token):
            return

        def processor(sess, dm):
            dm.hidden = not dm.hidden
            return True

        yield from _process_dmail_message(dispatcher, msg_dbid, processor)

        if redirect:
            dispatcher.send_301(redirect)
        else:
            dispatcher.send_204()
    elif req.startswith("/set_autoscan/"):
        params = req[14:]

        pq = params.find("?redirect=")
        if pq != -1:
            redirect = unquote(params[pq+10:])
        else:
            redirect = None
            pq = len(params)

        p0 = params.index('/', 0, pq)
        p1 = params.index('/', p0+1, pq)

        csrf_token = params[:p0]
        addr_id = int(params[p0+1:p1])
        interval = int(params[p1+1:pq])

        if not dispatcher.check_csrf_token(csrf_token):
            return

        def processor(sess, addr):
            addr.scan_interval = interval
            return True

        addr =\
            yield from _process_dmail_address(\
                dispatcher, processor, addr_id, fetch_keys=True)

        dispatcher.client_engine.update_dmail_autoscan(addr)

        if redirect:
            dispatcher.send_301(redirect)
        else:
            dispatcher.send_204()
    elif req.startswith("/empty_trash/"):
        params = req[13:]

        pq = params.find("?redirect=")
        if pq != -1:
            redirect = unquote(params[pq+10:])
        else:
            redirect = None
            pq = len(params)

        p0 = params.index('/', 0, pq)

        csrf_token = params[:p0]
        addr_enc = params[p0+1:pq]

        if not dispatcher.check_csrf_token(csrf_token):
            return

        yield from _empty_trash(dispatcher, addr_enc)

        if redirect:
            dispatcher.send_301(redirect)
        else:
            dispatcher.send_204()
    elif req.startswith("/make_address_default/"):
        params = req[22:]

        pq = params.find("?redirect=")
        if pq != -1:
            redirect = unquote(params[pq+10:])
        else:
            redirect = None
            pq = len(params)

        p0 = params.index('/')

        csrf_token = params[:p0]
        addr_dbid = params[p0+1:pq]

        if not dispatcher.check_csrf_token(csrf_token):
            return

        yield from _set_default_dmail_address(dispatcher, addr_dbid)

        if redirect:
            dispatcher.send_301(redirect)
        else:
            dispatcher.send_204()

##### OLD:

    elif req == "/create_address":
        if dispatcher.handle_cache(req):
            return

        template = templates.dmail_create_address[0]

        template = template.format(\
            csrf_token=dispatcher.client_engine.csrf_token)

        dispatcher.send_content([template, req])
    elif req.startswith("/address_config/"):
        params = req[16:]

        if params:
            addr_enc = params

            dmail_address = yield from\
                _load_dmail_address(\
                    dispatcher, site_key=mbase32.decode(addr_enc),\
                    fetch_keys=True)
        else:
            dmail_address = yield from\
                _load_default_dmail_address(dispatcher, fetch_keys=True)
            if dmail_address:
                addr_enc = mbase32.encode(dmail_address.site_key)
            else:
                dispatcher.send_content(\
                    "No dmail addresses, please create one first.")
                return

        content = templates.dmail_address_config[0]

        content = content.replace(\
            "{csrf_token}",\
            dispatcher.client_engine.csrf_token)
        content = content.replace(\
            "${DIFFICULTY}",\
            str(dmail_address.keys[0].difficulty))
        content = content.replace(\
            "${DMAIL_ADDRESS_SHORT}", addr_enc[:32])
        content = content.replace(\
            "${DMAIL_ADDRESS}", addr_enc)
        content = content.replace(\
            "${PRIVATE_KEY}",\
            base58.encode(dmail_address.site_privatekey))
        content = content.replace(\
            "${X}", base58.encode(dmail_address.keys[0].x))
        content = content.replace(\
            "${TARGET_KEY}",\
            mbase32.encode(dmail_address.keys[0].target_key))

        dispatcher.send_content(content)
##### OLD ACTIONS:
    elif req.startswith("/create_address/make_it_so?"):
        query = req[27:]

        qdict = parse_qs(query, keep_blank_values=True)

        prefix = qdict["prefix"][0]
        difficulty = int(qdict["difficulty"][0])
        csrf_token = qdict["csrf_token"][0]

        if not dispatcher.check_csrf_token(csrf_token):
            return

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
                " [<a target=\"_self\" href=\"morphis://.dmail/"\
                "address_config/{}\">Address Settings</a>] link, and then"\
                " click the \"Republish Dmail Site\" button.</p>"\
                    .format(dmail_key_enc).encode())

        dispatcher.send_partial_content(\
            '<p>New dmail address: <a href="morphis://.dmail/wrapper/'\
            '{addr_enc}">{addr_enc}</a></p>'\
                .format(addr_enc=dmail_key_enc).encode())
        dispatcher.send_partial_content(templates.dmail_frame_end)
        dispatcher.end_partial_content()
    elif req.startswith("/save_address_config/publish?"):
        query = req[29:]

        qdict = parse_qs(query, keep_blank_values=True)

        addr_enc = qdict["dmail_address"][0]
        difficulty = qdict["difficulty"][0]
        csrf_token = qdict["csrf_token"][0]

        if not dispatcher.check_csrf_token(csrf_token):
            return

        def processor(sess, dmail_address):
            if difficulty != dmail_address.keys[0].difficulty:
                dmail_address.keys[0].difficulty = difficulty
                return True
            else:
                return False

        dmail_address = yield from\
            _process_dmail_address(\
                dispatcher, processor, site_key=mbase32.decode(addr_enc),\
                fetch_keys=True)

        dh = dhgroup14.DhGroup14()
        dh.x = sshtype.parseMpint(dmail_address.keys[0].x)[1]
        dh.generate_e()

        dms = dmail.DmailSite()
        root = dms.root
        root["ssm"] = "mdh-v1"
        root["sse"] = base58.encode(sshtype.encodeMpint(dh.e))
        root["target"] =\
            mbase32.encode(dmail_address.keys[0].target_key)
        root["difficulty"] = int(difficulty)

        private_key = rsakey.RsaKey(privdata=dmail_address.site_privatekey)

        de = dmail.DmailEngine(\
            dispatcher.node.chord_engine.tasks, dispatcher.node.db)

        storing_nodes = yield from de.publish_dmail_site(private_key, dms)

        if storing_nodes:
            dispatcher.send_content(\
                templates.dmail_addr_settings_edit_success_content[0]\
                    .format(addr_enc, addr_enc[:32]).encode())
        else:
            dispatcher.send_content(\
                templates.dmail_addr_settings_edit_fail_content[0]\
                    .format(addr_enc, addr_enc[:32]).encode())
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

        dm, submit = yield from _read_dmail_post(dispatcher, data)

        if not dm:
            # Invalid csrf_token.
            return

        if submit:
            if submit == "send":
                tag = "Outbox"
            else:
                assert submit == "draft"
                tag = "Drafts"
        else:
            tag = "Drafts"

        dm = yield from _save_outgoing_dmail(dispatcher, dm, tag)

        if tag == "Drafts":
            log.info("Storing Dmail in Drafts tag.")
            dispatcher.send_content(\
                "SAVED.<br/><p>Dmail successfully saved to Drafts.</p>")
            return

        dispatcher.send_partial_content(\
            "<!DOCTYPE html>\n"\
                "<p>Message saved to Outbox; sending...</p>",\
            start=True)

        log.info("Sending submitted Dmail.")

        de =\
            dmail.DmailEngine(\
                dispatcher.node.chord_engine.tasks, dispatcher.node.db)

        sender_asymkey =\
            rsakey.RsaKey(privdata=dm.address.site_privatekey)\
                if dm.sender_dmail_key else None

        dest_addr = (dm.destination_dmail_key, dm.destination_significant_bits)

        storing_nodes =\
            yield from de.send_dmail(\
                sender_asymkey,\
                dest_addr,\
                dm.subject,\
                dm.date,\
                dm.parts[0].data)

        dest_addr_enc = mbase32.encode(dm.destination_dmail_key)

        if storing_nodes is False:
            dispatcher.send_partial_content(\
                "FAIL.<br/><p>Could not fetch destination's Dmail site,"\
                    " try again later; message remains in Outbox.</p>"\
                        .format(dest_addr_enc))
            dispatcher.end_partial_content()
            return
        elif not storing_nodes:
            dispatcher.send_partial_content(\
                "FAIL.<br/><p>Dmail timed out being stored on the network;"\
                    " message remains in Outbox.</p>"\
                        .format(dest_addr_enc))
            dispatcher.end_partial_content()
            return

        dispatcher.send_partial_content(\
            "SUCCESS.<br/><p>Dmail successfully sent to: {}</p>"\
                .format(dest_addr_enc))
        dispatcher.end_partial_content()

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
def _create_tag(dispatcher, tag_name):
    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            q = sess.query(func.count("*")).select_from(DmailTag)\
                .filter(DmailTag.name == tag_name)

            if q.scalar():
                return False

            tag = DmailTag()
            tag.name = tag_name

            sess.add(tag)

            sess.commit()

            return True

    r = yield from dispatcher.loop.run_in_executor(None, dbcall)

    return r

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

    if not dispatcher.check_csrf_token(dd["csrf_token"][0]):
        return None, None

    dm = DmailMessage()

    subject = dd.get("subject")
    if subject:
        dm.subject = subject[0]
    else:
        dm.subject = ""

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
        if owner_if_anon and owner_if_anon[0]:
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

    dm.date = mutil.utc_datetime()

    dm.hidden = False
    dm.read = True
    dm.deleted = False

    submit = dd.get("submit")
    if submit:
        return dm, submit[0]
    else:
        return dm, None

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
def _load_dmail_address(dispatcher, dbid=None, site_key=None,\
        fetch_keys=False):
    "Fetch from our database the parameters that are stored in a DMail site."

    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            q = sess.query(DmailAddress)

            if fetch_keys:
                q = q.options(joinedload("keys"))

            if dbid:
                q = q.filter(DmailAddress.id == dbid)
            elif site_key:
                q = q.filter(DmailAddress.site_key == site_key)
            else:
                raise Exception("Either dbid or site_key must be specified.")

            dmailaddr = q.first()

            if not dmailaddr:
                return None

            sess.expunge_all()

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
def _load_default_dmail_address(dispatcher, fetch_keys=False):
    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            q = sess.query(NodeState)\
                .filter(NodeState.key == consts.NSK_DEFAULT_ADDRESS)

            ns = q.first()

            if ns:
                q = sess.query(DmailAddress)\
                    .filter(DmailAddress.id == int(ns.value))
                if fetch_keys:
                    q = q.options(joinedload("keys"))
                addr = q.first()

                if addr:
                    sess.expunge_all()
                    return addr

            addr = sess.query(DmailAddress)\
                .order_by(DmailAddress.id)\
                .limit(1)\
                .first()

            if addr:
                sess.expire_on_commit = False

                ns = NodeState()
                ns.key = consts.NSK_DEFAULT_ADDRESS
                ns.value = str(addr.id)
                sess.add(ns)

                sess.commit()

                sess.expunge_all()

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
                q = q.filter(DmailMessage.hidden == True)\
                    .filter(DmailMessage.deleted == False)
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
                q = q.filter(DmailMessage.hidden == True)\
                    .filter(DmailMessage.deleted == False)
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
def _load_tags(dispatcher, exclude_tags=None):
    def dbcall():
        with dispatcher.node.db.open_session(True) as sess:
            q = sess.query(DmailTag).group_by(DmailTag.name)

            if exclude_tags:
                q = q.filter(~DmailTag.name.in_(exclude_tags))

            return q.all()

    tags = dispatcher.node.loop.run_in_executor(None, dbcall)

    return tags

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

    show_sender = tag not in ("Outbox", "Sent", "Drafts")

    for msg in msgs:
        unread = "" if msg.read else "new-mail"

        mail_icon = "new-mail-icon" if unread else "mail-icon"

        subject = msg.subject
        if subject:
            subject = subject.replace('"', "&quot;")
        else:
            subject = "[no subject]"

        safe_reply_subject = generate_safe_reply_subject(msg)

        sender_class = ""

        if show_sender:
            addr_key = msg.sender_dmail_key
            if addr_key:
                addr_value = mbase32.encode(addr_key)
                if not msg.sender_valid:
                    sender_class = " invalid_sender"
            else:
                addr_value = None
        else:
            addr_key = msg.destination_dmail_key
            if addr_key:
                addr_value = mbase32.encode(addr_key)
            else:
                addr_value = None

        if not addr_value:
            addr_value = "[Anonymous]"

        row = row_template.format(
            csrf_token=dispatcher.client_engine.csrf_token,\
            mail_icon=mail_icon,\
            tag=tag,\
            unread=unread,\
            addr=addr_enc,\
            msg_id=msg.id,\
            subject=subject,\
            safe_reply_subject=safe_reply_subject,\
            sender_class=sender_class,\
            sender=addr_value,\
            timestamp=mutil.format_human_no_ms_datetime(msg.date))

        dispatcher.send_partial_content(row)

@asyncio.coroutine
def _load_dmail(dispatcher, dmail_dbid, fetch_parts=False, fetch_tags=False):
    def dbcall():
        with dispatcher.node.db.open_session(True) as sess:
            q = sess.query(DmailMessage)

            if fetch_parts:
                q = q.options(joinedload("parts"))
            if fetch_tags:
                q = q.options(joinedload("tags"))

            q = q.filter(DmailMessage.id == dmail_dbid)

            dm = q.first()

            sess.expunge_all()

            return dm

    dm = yield from dispatcher.node.loop.run_in_executor(None, dbcall)

    return dm

@asyncio.coroutine
def _process_dmail_message(dispatcher, msg_dbid, process_call,\
        fetch_parts=False, fetch_tags=False):
    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            q = sess.query(DmailMessage)
            if fetch_parts:
                q = q.options(joinedload("parts"))
            if fetch_tags:
                q = q.options(joinedload("tags"))
            q = q.filter(DmailMessage.id == msg_dbid)

            dm = q.first()

            if process_call(sess, dm):
                sess.expire_on_commit = False
                sess.commit()

            sess.expunge_all()

            return dm

    dm = yield from dispatcher.node.loop.run_in_executor(None, dbcall)

    return dm

@asyncio.coroutine
def _load_first_address_with_new_mail(dispatcher):
    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            q = sess.query(DmailAddress)\
                .filter(\
                    DmailAddress.messages.any(\
                        and_(\
                            DmailMessage.read == False,\
                            DmailMessage.hidden == False,\
                            DmailMessage.tags.any(DmailTag.name == "Inbox"))))

            return q.first()

    dmail_address = yield from dispatcher.loop.run_in_executor(None, dbcall)

    return dmail_address

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
def _empty_trash(dispatcher, addr_enc):
    addr_site_key = mbase32.decode(addr_enc)

    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            # Immediately delete messages that we sent.
            q = sess.query(DmailMessage)\
                .filter(\
                    DmailMessage.address.has(\
                        DmailAddress.site_key == addr_site_key))\
                .filter(DmailMessage.hidden == True)\
                .filter(DmailMessage.destination_dmail_key != None)

            q.delete(synchronize_session=False)

            # Mark messages that we received for deletion later. We can't
            # actually delete them until we no longer check the target_id they
            # came from, else we will pick them up again.
            q = sess.query(DmailMessage)\
                .filter(\
                    DmailMessage.address.has(\
                        DmailAddress.site_key == addr_site_key))\
                .filter(DmailMessage.hidden == True)

            msgs = q.all()

            for msg in msgs:
                msg.tags.clear()
                msg.sender_dmail_key = None
                msg.destination_dmail_key = None
                msg.destination_significant_bits = None
                msg.subject = ""
                msg.date = mutil.utc_datetime()
                msg.parts.clear()
                msg.read = False
                msg.hidden = True
                msg.deleted = True

            sess.commit()

    yield from dispatcher.node.loop.run_in_executor(None, dbcall)

@asyncio.coroutine
def _process_dmail_address(dispatcher, process_call, dbid=None, site_key=None,\
    fetch_keys=False):
    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            q = sess.query(DmailAddress)

            if fetch_keys:
                q = q.options(joinedload("keys"))

            if dbid:
                q = q.filter(DmailAddress.id == dbid)
            elif site_key:
                q = q.filter(DmailAddress.site_key == site_key)
            else:
                raise Exception("Either dbid or site_key must be specified.")

            dmail_address = q.first()

            if process_call(sess, dmail_address):
                sess.expire_on_commit = False
                sess.commit()

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

    dmail_address =\
        yield from _load_dmail_address(dispatcher, site_key=dmail_addr)

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
    out = []
    len_text = len(text)
    p0 = 0
    while p0 < len_text:
        max_next = p0 + limit

        p1 = text.find('\n', p0, max_next)
        if p1 != -1:
            out.append(text[p0:p1])
            p0 = p1 + 1
            continue

        pd = text.rfind('-', p0, max_next)
        ps = text.rfind(' ', p0, max_next)
        p1 = max(pd, ps)

        if p1 == -1:
            out.append(text[p0:max_next])
            p0 += limit
            continue

        out.append(text[p0:p1])

        p0 = p1
        if p1 == ps:
            # Skip the space we broke the line at.
            p0 += 1

    return '\n'.join(out)

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

def generate_safe_reply_subject(dm, m32=False):
    reply_subject = dm.subject if dm.subject.startswith("Re: ")\
        else "Re: " + dm.subject
    if m32:
        return mbase32.encode(reply_subject.encode())
    else:
        return quote_plus(reply_subject)
