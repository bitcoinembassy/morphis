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
            "<a href='/.dds/synapse'>synapse</a><br/>"\
            "<a href='/.dds/neuron'>neuron</a><br/>")
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
    elif req.startswith("/read/content/"):
        yield from _process_read_content(dispatcher, req[14:])
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
def _process_neuron(dispatcher):
    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            q = sess.query(Synapse)

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
                "<iframe src='http://localhost:4252/.dds/read/content/{key}/{target_key}' style='height: 25%; width: 100%;'></iframe>"\
                    .format(key=mbase32.encode(key),\
                        target_key=mbase32.encode(synapse.axon_addr))

            dispatcher.send_partial_content(msg)

        yield from dp.scan_targeted_blocks(synapse.axon_addr, 20, cb)

    dispatcher.end_partial_content()

@asyncio.coroutine
def _process_read_content(dispatcher, req):
    p0 = req.index('/')
    key = mbase32.decode(req[:p0])
    target_key = mbase32.decode(req[p0+1:])


    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            t = sess.query(AxonKey).first()
            log.info("AN X=[{}].".format(mbase32.encode(t.x)))

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

            log.info(\
                "Found AxonKey (x=[{}])!".format(mbase32.encode(axon_key.x)))

            sess.expunge_all()

            return axon_key

    axon_key = yield from dispatcher.loop.run_in_executor(None, dbcall)

    if axon_key:
        log.info("YES FOUND!")

        de =\
            DmailEngine(\
                dispatcher.node.chord_engine.tasks, dispatcher.node.db)

        l, x = sshtype.parseMpint(axon_key.x)
        dm, sender_auth_valid = yield from\
            de.fetch_dmail(bytes(key), x, target_key=target_key)

        msg_txt = ""
        if not sender_auth_valid:
            msg_txt += "[WARNING: SENDER ADDRESS IS FORGED]\n"

        msg_txt = dmail._format_dmail_content(dm.parts)

        dispatcher.send_content(msg_txt)
    else:
        log.info("NOT FOUND!")

        data_rw =\
            yield from\
                dispatcher.node.chord_engine.tasks.send_get_targeted_data(\
                    bytes(key))

        if not data_rw.data:
            return

        msg = "{}".format(hex_dump(data_rw.data))

        acharset = dispatcher.get_accept_charset()
        dispatcher.send_content(\
            msg, content_type="text/plain; charset={}".format(acharset))
