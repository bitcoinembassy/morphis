# Copyright (c) 2016  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
from concurrent import futures
from datetime import datetime
import logging
from urllib.parse import parse_qs
import os

from sqlalchemy import or_

import consts
from db import User, DdsPost
from dmail import DmailEngine
from dds import DdsEngine
import dpush
import enc
import maalstroom.dmail as dmail
import maalstroom.templates as templates
import mbase32
from morphisblock import MorphisBlock
from mutil import fia, hex_dump, make_safe_for_html_content
import mutil
import synapse as syn
import targetedblock as tb
import sshtype

log = logging.getLogger(__name__)

S_DDS = ".dds"

class MaalstroomRequest(object):
    def __init__(self, dispatcher, service, rpath):
        assert type(service) is str
        self.dispatcher = dispatcher
        self.service = service
        self.path, sep, self.query = rpath.partition('?')
        self.req = self.path[len(service):]

        log.info("req=[{}].".format(self.req))

        if self.query:
            self.qdict = parse_qs(self.query, keep_blank_values=True)
        else:
            self.qdict = {}

class DdsRequest(MaalstroomRequest):
    def __init__(self, dispatcher, rpath):
        super().__init__(dispatcher, ".dds", rpath)

        self._ident_enc = None
        self.ident_enc_ = False
        self._ident = None
        self.ident_ = False

    @property
    def ident_enc(self):
        if not self.ident_enc_:
            self.ident_enc_ = True
            self._ident_enc = fia(self.qdict.get("ident"))
        return self._ident_enc

    @property
    def ident(self):
        if not self.ident_:
            self.ident_ = True
            if self.ident_enc:
                self._ident = mbase32.decode(self.ident_enc)
            elif self._ident_enc is None:
                self._ident = None # Default.
            else:
                assert self._ident_enc == ""
                self._ident = b"" # Anonymous.

        return self._ident

    @ident.setter
    def ident(self, value):
        self._ident = value
        if value == b"":
            self._ident_enc = ""
            return
        self._ident_enc = mbase32.encode(value)
        self.ident_enc_ = True

    @ident_enc.setter
    def ident_enc(self, value):
        self._ident_enc = value
        if value == "":
            self._ident = b""
            return
        self._ident = mbase32.decode(value)
        self.ident_ = True

@asyncio.coroutine
def serve_get(dispatcher, rpath):
    log.info("Service .dds request.")

    mr = DdsRequest(dispatcher, rpath)
    req = mr.req

    if req == "" or req == "/":
        yield from _process_root(mr)
    elif req == "/style.css":
        dispatcher.send_content(templates.dds_css[0], content_type="text/css")
    elif req.startswith("/images/"):
        dispatcher.send_content(templates.dds_imgs[req[8:]])
    elif req == "/axon/create":
        # Render the Create Axon (Targeted or not) page.
        yield from _process_axon_create(dispatcher, req[5:])
    elif req.startswith("/axon/grok/"):
        # Render the Grok View; which shows the Axon, SynapseS and Synapse
        # create form.
        yield from _process_axon_grok(dispatcher, req[11:])
    elif req.startswith("/axon/read/"):
        # Render an individual Axon.
        yield from _process_axon_read(dispatcher, req[11:])
    elif req.startswith("/axon/synapses/"):
        # Scan for and render SynapseS connected to the requested Axon.
        yield from _process_axon_synapses(dispatcher, req[15:])
    elif req.startswith("/synapse/create/"):
        # Render the Create Synapse entry form.
        yield from _process_synapse_create(dispatcher, req[16:])
    else:
        dispatcher.send_error("request: {}".format(req), errcode=400)

@asyncio.coroutine
def serve_post(dispatcher, rpath):
    assert rpath.startswith(S_DDS)

    log.info("Service .dds post.")

    req = rpath[len(S_DDS):]

    if req == "/synapse/create":
        yield from _process_synapse_create_post(dispatcher, req)
        return

    dispatcher.send_error("request: {}".format(req), errcode=400)

@asyncio.coroutine
def _process_root(req):
    random_id_enc = mbase32.encode(os.urandom(consts.NODE_ID_BYTES))

    template = templates.dds_main[0]
    template = template.format(random_id_enc=random_id_enc)

    if req.ident_enc is None:
        dmail_address = yield from dmail._load_default_dmail_address(\
            req.dispatcher, fetch_keys=True)
        if dmail_address:
            req.ident = dmail_address.site_key

    available_idents = yield from dmail.render_dmail_addresses(\
        req.dispatcher, req.ident, use_addr=True)

    template2 = templates.dds_identbar[0]
    template2 = template2.format(\
        current_ident=req.ident_enc, available_idents=available_idents)

    template = template2 + template

    wrapper = templates.dds_wrapper[0]
    wrapper =\
        wrapper.format(title="MORPHiS Maalstroom DDS", child=template)

    req.dispatcher.send_content(wrapper)

@asyncio.coroutine
def _process_axon_create(dispatcher, req):
    template = templates.dds_axon[0]
    template = template.format(\
        message_text="",
        csrf_token=dispatcher.client_engine.csrf_token,
        delete_class="display_none")

    dispatcher.send_content([template, req])

@asyncio.coroutine
def _process_axon_grok(dispatcher, req):
    if req.startswith("@"):
        key = DdsEngine.calc_key_for_channel(req[1:])
        significant_bits = None
    else:
        key, significant_bits = dispatcher.decode_key(req)

        if not key:
            dispatcher.send_error(\
                "Invalid encoded key: [{}].".format(req), 400)
            return

    if significant_bits:
        # Support prefix keys.
        key = yield from dispatcher.fetch_key(key, significant_bits)

        if not key:
            return

    msg = "<iframe src='morphis://.dds/axon/read/{key}'"\
        " style='height: 10em; width: 100%; border: 1;'"\
        " seamless='seamless'></iframe><iframe"\
        " src='morphis://.dds/axon/synapses/{key}#new'"\
        " style='height: calc(100% - 17.5em); width: 100%; border: 0;'"\
        " seamless='seamless'></iframe><iframe"\
        " src='morphis://.dds/synapse/create/{key}'"\
        " style='height: 7em; width: 100%; border: 1;'"\
        " seamless='seamless'></iframe>"\
            .format(key=mbase32.encode(key))

    dispatcher.send_content(msg)
    return

@asyncio.coroutine
def _process_axon_read(dispatcher, req):
    p0 = req.find('/')

    if p0 > -1:
        # Then the request is for a TargetedBlock.
        key = mbase32.decode(req[:p0])
        target_key = mbase32.decode(req[p0+1:])
    else:
        # Then the request is not for a TargetedBlock.
        key = mbase32.decode(req)
        target_key = None

    post = yield from retrieve_post(dispatcher.node, key, target_key)

    if not post:
        dispatcher.send_content("Not found on the network at the moment.")
        return

    key_enc = mbase32.encode(key)

    content = yield from _format_axon(dispatcher.node, post.data, key, key_enc)

    timestr = mutil.format_human_no_ms_datetime(post.timestamp)

    template = templates.dds_synapse_view[0]
    template = template.format(key=key_enc, content=content, timestamp=timestr)

    msg = "<head><link rel='stylesheet' href='morphis://.dds/style.css'>"\
        "</link></head><body style='height: 90%; padding:0;margin:0;'>{}"\
        "</body>"\
            .format(template)

    content_type = "text/html; charset={}"\
        .format(dispatcher.get_accept_charset())

    dispatcher.send_content(msg, content_type=content_type)
    return

@asyncio.coroutine
def _process_axon_synapses(dispatcher, axon_addr_enc):
    axon_addr = mbase32.decode(axon_addr_enc)

    dispatcher.send_partial_content(templates.dds_axon_synapses_start[0], True)

    loaded = {}

    @asyncio.coroutine
    def process_post(post):
        assert type(post) in (syn.Synapse, DdsPost)

        if type(post) is syn.Synapse:
            synapse = post
            key = synapse.synapse_key
            post = yield from retrieve_post(dispatcher.node, synapse)
        else:
            key = post.synapse_key
            if not key:
                key = post.data_key

        if not post:
            dispatcher.send_partial_content(\
                "Not found on the network at the moment.")
            return

        key_enc = mbase32.encode(key)

        content =\
            yield from _format_axon(dispatcher.node, post.data, key, key_enc)

        timestr = mutil.format_human_no_ms_datetime(post.timestamp)

        template = templates.dds_synapse_view[0]
        template =\
            template.format(key=key_enc, content=content, timestamp=timestr)

        dispatcher.send_partial_content(template)

        if post.synapse_key:
            loaded[post.synapse_key] = True
        if post.synapse_pow:
            loaded[post.synapse_pow] = True
        loaded[post.data_key] = True

    def dbcall():
        with dispatcher.node.db.open_session() as sess:
            q = sess.query(DdsPost)\
                .filter(DdsPost.target_key == axon_addr)\
                .order_by(DdsPost.timestamp)

            return q.all()

    posts = yield from dispatcher.loop.run_in_executor(None, dbcall)

    for post in posts:
        yield from process_post(post)

    dispatcher.send_partial_content("<hr id='new'/>")

    new_tasks = []

    @asyncio.coroutine
    def cb(key):
        nonlocal new_tasks

        key_enc = mbase32.encode(key)

        if loaded.get(bytes(key)):
            log.info("Skipping already loaded synapse for key=[{}]."\
                .format(key_enc))
            return

        raise Exception("TODO: YOU_ARE_HERE")
#        msg = "<iframe src='morphis://.dds/axon/read/{key}/{target_key}'"\
#            " style='height: 15em; width: 100%; border: 0;'"\
#            " seamless='seamless'></iframe>\n"\
#                .format(key=key_enc, target_key=axon_addr_enc)
#
#        dispatcher.send_partial_content(msg)

#    dp = dpush.DpushEngine(dispatcher.node)
#
#    yield from dp.scan_targeted_blocks(axon_addr, 8, cb)

    @asyncio.coroutine
    def cb2(data_rw):
        nonlocal new_tasks

        for synapse in data_rw.data:
            if loaded.get(bytes(synapse.synapse_key)):
                loaded[synapse.synapse_key] = True
                loaded[synapse.synapse_pow] = True
                if log.isEnabledFor(logging.INFO):
                    log.info("Skipping already loaded Synapse for key=[{}]."\
                        .format(mbase32.encode(synapse.synapse_key)))
                continue
            new_tasks.append(\
                asyncio.async(\
                    process_post(synapse),\
                    loop=dispatcher.node.loop))

    yield from dispatcher.node.engine.tasks.send_get_synapses(\
        axon_addr, result_callback=cb2, retry_factor=25)

    if new_tasks:
        yield from asyncio.wait(\
            new_tasks,\
            loop=dispatcher.node.loop,\
            return_when=futures.ALL_COMPLETED)

    dispatcher.send_partial_content(\
        "<div>Last refreshed: {}</div><span id='end' style='color: gray'/>"\
        "</body></html>"\
            .format(mutil.utc_datetime()))

    dispatcher.end_partial_content()

@asyncio.coroutine
def _process_synapse_create(dispatcher, target_addr):
    if dispatcher.handle_cache(target_addr):
        return

    template = templates.dds_create_synapse[0]

    template = template.format(\
        csrf_token=dispatcher.client_engine.csrf_token,\
        message_text="",\
        target_addr=target_addr)

    dispatcher.send_content(template)

@asyncio.coroutine
def _process_synapse_create_post(dispatcher, req):
    dd = yield from dispatcher.read_post()
    if not dd:
        dispatcher.send_error("request: {}".format(req), errcode=400)
        return

    content = fia(dd["content"])
    content2 = fia(dd.get("content2"))

    if not content:
        content = content2
    elif content2:
        content = content + "\r\n" + content2

    if not content:
        dispatcher.send_error("No content.", errcode=400)
        return

    key = None

    def key_callback(akey):
        nonlocal key
        key = akey

    yield from\
        dispatcher.node.chord_engine.tasks.send_store_data(\
            content.encode(), store_key=True, key_callback=key_callback)

    target_addr = fia(dd["target_addr"])

    if not target_addr:
        resp =\
            "Resulting&nbsp;<a href='morphis://.dds/axon/read/{axon_addr}'>"\
                "Axon</a>&nbsp;Address:<br/>{axon_addr}"\
                     .format(axon_addr=mbase32.encode(key))

        dispatcher.send_content(resp)
        return

    target_addr = mbase32.decode(target_addr)

    synapse = syn.Synapse.for_target(target_addr, key)

    yield from DdsEngine(dispatcher.node).upload_synapse(synapse)

    resp =\
        "Resulting&nbsp;<a href='morphis://.dds/axon/read/{synapse_addr}/"\
            "{target_addr}'>Synapse</a>&nbsp;Address:<br/>{synapse_addr}"\
                 .format(\
                    synapse_addr=mbase32.encode(key),\
                    target_addr=mbase32.encode(target_addr))

    dispatcher.send_content(resp)

@asyncio.coroutine
def _format_axon(node, data, key, key_enc=None):
    try:
        result = __format_post(data)
    except UnicodeDecodeError:
        synapse = syn.Synapse(data)

        data_rw = yield from\
                node.chord_engine.tasks.send_get_data(synapse.source_key)

        if not data_rw or data_rw.data is None:
            return "<NOT FOUND>"

        result = __format_post(data_rw.data)

    if not key_enc:
        key_enc = mbase32.encode(key)

    return result\
        + "<div style='font-family: monospace; font-size: 8pt;"\
            "color: #a0a0ff; position: absolute; bottom: 0.3em;"\
            "right: 0.3em;'>{}</div>".format(key_enc[:32])

def __format_post(data):
    fr = data.find(b'\r')
    fn = data.find(b'\n')

    if fr == -1 and fn == -1:
        return "<h3>{}</h3>".format(make_safe_for_html_content(data))

    if fr == -1:
        end = fn
        start = end + 1
    elif fn == -1:
        end = fr
        start = end + 1
    else:
        end = fr
        start = end + 2

    return "<h3 style='padding:0;margin:0;'>{}</h3>"\
        "<pre style='color: gray; padding:0;margin:0;'>{}</pre>"\
            .format(\
                data[:end].decode(), make_safe_for_html_content(data[start:]))

#TODO: Move to DdsEngine.

@asyncio.coroutine
def retrieve_post(node, key, target_key=None):
    synapse = None
    if type(key) is syn.Synapse:
        assert not target_key
        synapse = key
        key = synapse.synapse_key
        target_key = synapse.target_key

    post = yield from _load_dds_post(node, key)

    if post:
        return post

    if not target_key:
        # Plain static data.
        data_rw = yield from\
            node.chord_engine.tasks.send_get_data(bytes(key))

        obj = None
    else:
        # TargetedBlock or Synapse.
        if synapse:
            obj = synapse
        else:
            data_rw =\
                yield from node.chord_engine.tasks.send_get_targeted_data(\
                    bytes(key), target_key=target_key)
            obj = data_rw.object

        if obj:
            if type(obj) is syn.Synapse:
                data_rw = yield from\
                    node.chord_engine.tasks.send_get_data(obj.source_key)
            else:
                assert type(obj) is tb.TargetedBlock, type(obj)
                data_rw.data = data_rw.data[tb.TargetedBlock.BLOCK_OFFSET:]

    if not data_rw.data:
        return None

    # Cache the 'post' locally.
    post = yield from _save_dds_post(node, key, target_key, obj, data_rw.data)

    return post

@asyncio.coroutine
def _load_dds_post(node, key):
    def dbcall():
        with node.db.open_session() as sess:
            q = sess.query(DdsPost).filter(
                or_(\
                    DdsPost.synapse_key == key,\
                    DdsPost.synapse_pow == key,\
                    DdsPost.data_key == key))

            return q.first()

    return (yield from node.loop.run_in_executor(None, dbcall))

@asyncio.coroutine
def _save_dds_post(node, key, target_key, obj, data):
    def dbcall():
        with node.db.open_session() as sess:
            post = DdsPost()

            post.first_seen = mutil.utc_datetime()
            post.data = data

            if obj:
                assert target_key
                post.target_key = target_key

                if type(obj) is syn.Synapse:
                    post.synapse_key = obj.synapse_key
                    post.synapse_pow = obj.synapse_pow
                    post.data_key = obj.source_key
                    post.timestamp = mutil.utc_datetime(obj.timestamp)
                else:
                    assert type(obj) is tb.TargetedBlock, type(obj)
                    post.data_key = post.synapse_pow = key
                    post.timestamp = post.first_seen
            else:
                post.data_key = key
                post.timestamp = post.first_seen

            sess.add(post)

            sess.commit()

            # Make sure data is loaded for use by caller.
            len(post.data)

            sess.expunge_all()

            return post

    return (yield from node.loop.run_in_executor(None, dbcall))
