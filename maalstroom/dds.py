# Copyright (c) 2016  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
from datetime import datetime
import logging

from db import User, Neuron, Synapse
import maalstroom.dmail as dmail
import maalstroom.templates as templates
import mbase32
from mutil import fia

log = logging.getLogger(__name__)

s_dds = ".dds"
s_dds_len = len(".dds")

@asyncio.coroutine
def serve_get(dispatcher, rpath):
    log.info("Service .dds request.")

    req = rpath[s_dds_len:]

    if req == "" or req == "/":
        dispatcher.send_content("HI!")
        return
    elif req == "/test":
        dmail_address =\
            yield from dmail._load_default_dmail_address(dispatcher)

        if dmail_address:
            addr_enc = mbase32.encode(dmail_address.site_key)

        dispatcher.send_content(addr_enc)
        return
    elif req == "/neuron":
        if dispatcher.handle_cache(req):
            return

        template = templates.dds_neuron[0]
        template = template.format(\
            csrf_token=dispatcher.client_engine.csrf_token,
            delete_class="")

        dispatcher.send_content([template, req])
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
            Synapse s = Synapse()
            s.axon_addr = mbase32.decode(axon_addr)

    dispatcher.send_content(\
        "SYNAPSE CREATED!<br/>"\
        "<p>axon_addr [{}] successfully synapsed."\
            "</p>"\
            .format(axon_addr))
