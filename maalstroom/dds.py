# Copyright (c) 2016  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
from datetime import datetime
import logging

import mbase32
import maalstroom.dmail as dmail
import maalstroom.templates as templates

log = logging.getLogger(__name__)

s_dds = ".dds"
s_dds_len = len(".dds")

@asyncio.coroutine
def serve_get(dispatcher, rpath):
    global top_tags

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
    elif req == "/feed":
        if dispatcher.handle_cache(req):
            return

        template = templates.dds_feed[0]

        dispatcher.send_content([template, req])
        return

    dispatcher.send_error("request: {}".format(req), errcode=400)
