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
from mutil import fia, hex_dump
import sshtype

log = logging.getLogger(__name__)

s_dds = ".dds"
s_dds_len = len(".dds")

@asyncio.coroutine
def serve_get(dispatcher, rpath):
    log.info("Service .dds request.")

    req = rpath[s_dds_len:]

    if req == "" or req == "/":
        dispatcher.send_content(\
            "<a href='/.dds/axon'>axon</a><br/>"\
            "<a href='/.dds/synapse'>subscribe</a><br/>"\
            "<a href='/.dds/neuron'>feeds</a><br/>")
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
            msg = "MSG:&nbsp;[{key}]<br/>"\
                "<iframe src='morphis://.dds/axon/read/{key}/{target_key}' style='height: 7em; width: 100%;'></iframe>"\
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
        target_key = key
    else:
        key = mbase32.decode(req[:p0])
        target_key = mbase32.decode(req[p0+1:])

    #FIXME: Move this to after we know the axon signal is encrypted!
    # Unfortunately we will need to refactor the fetch_dmail(..) method first
    # for that.
    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            q = sess.query(Neuron)\
                .filter(Neuron.synapses.any(Synapse.axon_addr == target_key))

            sess.expunge_all()

            neuron = q.first()

            if not neuron:
                return None

            found = False
            for synapse in neuron.synapses:
                if synapse.axon_addr == target_key:
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

    axon_key = yield from dispatcher.loop.run_in_executor(None, dbcall)

    if axon_key:
        de =\
            DmailEngine(\
                dispatcher.node.chord_engine.tasks, dispatcher.node.db)

        if target_key is key:
            # Signal to fetch_dmail(..) not to try to verify the proof of work
            # since there will be none since this is not a targeted read
            # request.
            target_key = None

        l, x = sshtype.parseMpint(axon_key.x)
        dm, sender_auth_valid = yield from\
            de.fetch_dmail(bytes(key), x, target_key=target_key)

        msg_txt = ""
        if not sender_auth_valid:
            msg_txt += "[WARNING: SENDER ADDRESS IS FORGED]\n"

        msg_txt = dmail._format_dmail_content(dm.parts)

        dispatcher.send_content(msg_txt)
    else:
        data_rw =\
            yield from\
                dispatcher.node.chord_engine.tasks.send_get_targeted_data(\
                    bytes(key))

        if not data_rw.data:
            return

        if data_rw.data.startswith(MorphisBlock.UUID):
            msg = "{}".format(hex_dump(data_rw.data))
        else:
            msg = data_rw.data

        acharset = dispatcher.get_accept_charset()
        dispatcher.send_content(\
            msg, content_type="text/plain; charset={}".format(acharset))
