# Copyright (c) 2016  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
from datetime import datetime
import logging

from db import User, Neuron, Synapse, AxonKey
from dmail import DmailEngine
import dpush
import maalstroom.dmail as dmail
import maalstroom.templates as templates
import mbase32
from morphisblock import MorphisBlock
from targetedblock import TargetedBlock
from mutil import fia, hex_dump, make_safe_for_html_content
import sshtype

log = logging.getLogger(__name__)

s_dds = ".dds"
s_dds_len = len(".dds")

@asyncio.coroutine
def serve_get(dispatcher, rpath):
    log.info("Service .dds request.")

    req = rpath[s_dds_len:]

    if req == "" or req == "/":
        template = templates.dds_main[0]

        dispatcher.send_content(template)
        return
    elif req == "/test":
        dmail_address =\
            yield from dmail._load_default_dmail_address(dispatcher)

        if dmail_address:
            addr_enc = mbase32.encode(dmail_address.site_key)

        dispatcher.send_content(addr_enc)
        return
    elif req == "/synapse":
        if dispatcher.handle_cache(req):
            return

        template = templates.dds_neuron[0]
        template = template.format(\
            csrf_token=dispatcher.client_engine.csrf_token,
            delete_class="")

        dispatcher.send_content([template, req])
        return
    elif req == "/neuron":
        yield from _process_neuron(dispatcher)
        return
    elif req == "/axon":
        yield from _process_axon(dispatcher, req[5:])
        return
    elif req.startswith("/axon/read/"):
        yield from _process_read_axon(dispatcher, req[11:])
        return

    dispatcher.send_error("request: {}".format(req), errcode=400)

@asyncio.coroutine
def serve_post(dispatcher, rpath):
    assert rpath.startswith(s_dds)

    log.info("Service .dds post.")

    req = rpath[s_dds_len:]

    if req == "/synapse/create/make_it_so":
        yield from _process_create_synapse(dispatcher)
        return
    elif req == "/axon/create":
        yield from _process_create_axon(dispatcher)
        return

    dispatcher.send_error("request: {}".format(req), errcode=400)

@asyncio.coroutine
def _process_create_synapse(dispatcher):
    dd = yield from dispatcher.read_post()
    if not dd: return # Invalid csrf_token.

    axon_addr = fia(dd["axon_addr"])

    if not axon_addr:
        return

    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            s = Synapse()
            s.axon_addr = mbase32.decode(axon_addr)

            sess.add(s)

            sess.commit()

            return True

    r = yield from dispatcher.loop.run_in_executor(None, dbcall)

    dispatcher.send_content(\
        "SYNAPSE CREATED!<br/>"\
        "<p>axon_addr [{}] successfully synapsed."\
            "</p>"\
            .format(axon_addr))

@asyncio.coroutine
def _process_create_axon(dispatcher):
    dd = yield from dispatcher.read_post()
    if not dd: return

    content = fia(dd["content"])
    if not content:
        return

    key = None
    def key_callback(akey):
        nonlocal key
        key = akey

    content = content.encode()

    target_addr = fia(dd["target_addr"])

    if target_addr:
        target_addr = mbase32.decode(target_addr)

        de =\
            DmailEngine(\
                dispatcher.node.chord_engine.tasks, dispatcher.node.db)

        tb, tb_data =\
            yield from de.generate_targeted_block(target_addr, 20, content)

        yield from\
            dispatcher.node.chord_engine.tasks.send_store_targeted_data(\
                tb_data, store_key=True, key_callback=key_callback)

        resp =\
            "Resulting&nbsp;<a href='morphis://.dds/axon/read/{axon_addr}/"\
                "{target_addr}'>Axon</a>&nbsp;Address:<br/>{axon_addr}"\
                     .format(\
                        axon_addr=mbase32.encode(key),\
                        target_addr=mbase32.encode(target_addr))
    else:
        yield from\
            dispatcher.node.chord_engine.tasks.send_store_data(\
                content, store_key=True, key_callback=key_callback)

        resp =\
            "Resulting&nbsp;<a href='morphis://.dds/axon/read/{axon_addr}'>"\
                "Axon</a>&nbsp;Address:<br/>{axon_addr}"\
                     .format(axon_addr=mbase32.encode(key))

    dispatcher.send_content(resp)

@asyncio.coroutine
def _process_neuron(dispatcher):
    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            q = sess.query(Synapse).filter(Synapse.disabled == False)

            return q.all()

    synapses = yield from dispatcher.loop.run_in_executor(None, dbcall)

    dp = dpush.DpushEngine(dispatcher.node)

    dispatcher.send_partial_content("<p>Signals</p>", True)

    for synapse in synapses:
        dispatcher.send_partial_content(\
            "Address:&nbsp;[{}]<br/><br/>"\
                .format(mbase32.encode(synapse.axon_addr)))

        @asyncio.coroutine
        def cb(key):
            msg = "<iframe src='morphis://.dds/axon/read/{key}/{target_key}' style='height: 5.5em; width: 100%; border: 0;' seamless='seamless'></iframe>"\
                .format(key=mbase32.encode(key),\
                    target_key=mbase32.encode(synapse.axon_addr))

            dispatcher.send_partial_content(msg)

        yield from dp.scan_targeted_blocks(synapse.axon_addr, 20, cb)

    dispatcher.end_partial_content()

@asyncio.coroutine
def _process_axon(dispatcher, req):
    template = templates.dds_axon[0]
    template = template.format(\
        message_text="",
        csrf_token=dispatcher.client_engine.csrf_token,
        delete_class="")

    dispatcher.send_content([template, req])

@asyncio.coroutine
def _process_read_axon(dispatcher, req):
    p0 = req.find('/')
    if p0 == -1:
        key = mbase32.decode(req)
        target_key = None

        data_rw =\
            yield from\
                dispatcher.node.chord_engine.tasks.send_get_data(\
                    bytes(key))
    else:
        key = mbase32.decode(req[:p0])
        target_key = mbase32.decode(req[p0+1:])

        data_rw =\
            yield from\
                dispatcher.node.chord_engine.tasks.send_get_targeted_data(\
                    bytes(key), target_key=target_key)

    data = data_rw.data

    if not data:
        dispatcher.send_content("Not found on the network at the moment.")
        return

    if not data.startswith(MorphisBlock.UUID):
        # Plain data, return it!
        msg = _format_post(data, key)

        acharset = dispatcher.get_accept_charset()
        dispatcher.send_content(\
            msg, content_type="text/html; charset={}".format(acharset))
        return

    # We assume it is a Dmail if it is a MorphisBlock.
    de =\
        DmailEngine(\
            dispatcher.node.chord_engine.tasks, dispatcher.node.db)

    axon_key = yield from __load_axon_key(\
            dispatcher,\
            target_key if target_key else key)

    if not axon_key:
        # If we can't decrypt it, send a hexdump.
        msg = hexdump(data)

        acharset = dispatcher.get_accept_charset()
        dispatcher.send_content(\
            msg, content_type="text/plain; charset={}".format(acharset))
        return

    l, x = sshtype.parseMpint(axon_key.x)

    dm, sender_auth_valid = yield from\
        de.fetch_dmail(bytes(key), x, data_rw)

    msg_txt = ""
    if not sender_auth_valid:
        msg_txt += "[WARNING: SENDER ADDRESS IS FORGED]\n"

    msg_txt = dmail._format_dmail_content(dm.parts)

    #FIXME: Move this into dmail._format_dmail_content(..) above.
    msg_txt = make_safe_for_html_content(msg_txt)

    dispatcher.send_content(msg_txt)

def _format_post(data, key):
    return __format_post(data)\
        + "<div style='color: #7070ff; position:absolute; bottom: 0;"\
            "right: 0;'>{}</div>".format(mbase32.encode(key))

def __format_post(data):
    fr = data.find(b'\r')
    fn = data.find(b'\n')

    if fr == -1 and fn == -1:
        return "<body style='padding:0;margin:0;'><h3>{}</h3></body>".format(make_safe_for_html_content(data))

    if fr == -1:
        end = fn
        start = end + 1
    elif fn == -1:
        end = fr
        start = end + 1
    else:
        end = fr
        start = end + 2

    return "<body style='padding:0;margin:0;'>"\
        "<h3 style='padding:0;margin:0;'>{}</h3>"\
        "<pre style='color: gray; padding:0;margin:0;'>{}</pre></body>"\
            .format(\
                data[:end].decode(), make_safe_for_html_content(data[start:]))

@asyncio.coroutine
def __load_axon_key(dispatcher, axon_addr):
    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            q = sess.query(Neuron)\
                .filter(Neuron.synapses.any(Synapse.axon_addr == axon_addr))

            sess.expunge_all()

            neuron = q.first()

            if not neuron:
                return None

            found = False
            for synapse in neuron.synapses:
                if synapse.axon_addr == axon_addr:
                    found = True
                    break

            assert found

            axon_key = synapse.axon_keys[0]

            if log.isEnabledFor(logging.INFO):
                log.info(\
                    "Found AxonKey (x=[{}])!"\
                        .format(mbase32.encode(axon_key.x)))

            sess.expunge_all()

            return axon_key

    return (yield from dispatcher.loop.run_in_executor(None, dbcall))
