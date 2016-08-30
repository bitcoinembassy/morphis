# Copyright (c) 2016  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
from concurrent import futures
from datetime import datetime
import json
import logging
import time
from urllib.parse import parse_qs, quote_plus
import os

from sqlalchemy import or_, and_, desc

import consts
from db import User, DdsPost, NodeState
from dmail import DmailEngine
from clientengine.dds import DdsQuery
from dds import DdsEngine
import dpush
import enc
import maalstroom.dmail as dmail
import maalstroom.templates as templates
import mbase32
from morphisblock import MorphisBlock
from mutil import fia, hex_dump, make_safe_for_html_content
import mutil
import rsakey
import synapse as syn
import sshtype

log = logging.getLogger(__name__)

S_DDS = ".dds"
DEFAULT_FEED_KEY = "dds.feeds.default"

class MaalstroomRequest(object):
    def __init__(self, dispatcher, service, rpath):
        assert type(service) is str
        self.dispatcher = dispatcher
        self.service = service
        self.rpath = rpath
        self.path, sep, self._query = rpath.partition('?')
        self.req = self.path[len(service):]

        if self._query:
            self.qdict = parse_qs(self._query, keep_blank_values=True)
            self._query = '?' + self._query
        else:
            self.qdict = {}

        self._modified = False # True means self.query needs rebuild.

    @property
    def modified(self):
        return self._modified

    def set_modified(self):
        self._modified = True

class DdsRequest(MaalstroomRequest):
    def __init__(self, dispatcher, rpath):
        super().__init__(dispatcher, ".dds", rpath)

        self._ident_enc = None
        self.__ident_enc = False
        self._ident = None
        self.__ident = False

    @asyncio.coroutine
    def process(self):
        if self.ident is None:
            dmail_address = yield from dmail._load_default_dmail_address(\
                self.dispatcher.node, fetch_keys=True)
            if dmail_address:
                self.ident = dmail_address.site_key

    @property
    def ident_enc(self):
        if self.__ident_enc:
            return self._ident_enc

        self.__ident_enc = True
        self._ident_enc = fia(self.qdict.get("ident"))

        return self._ident_enc

    @property
    def ident(self):
        if self.__ident:
            return self._ident

        self.__ident = True
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
        self.set_modified()

        self._ident = value

        if value is None:
            self._ident_enc = None
            return
        elif not value:
            assert value == b""
            self._ident_enc = ""
            return

        self._ident_enc = mbase32.encode(value)
        self.ident_enc_ = True

    @ident_enc.setter
    def ident_enc(self, value):
        self.set_modified()

        self._ident_enc = value

        if value is None:
            self._ident = None
            return
        elif not value:
            assert value == ""
            self._ident = b""
            return

        self._ident = mbase32.decode(value)
        self.ident_ = True

    @property
    def query(self):
        if self._query and not self.modified:
            return self._query

        if self.ident_enc is not None:
            self._query = "?ident={}".format(self.ident_enc)
        else:
            self._query = ""

        return self._query

@asyncio.coroutine
def serve_get(dispatcher, rpath):
    log.info("Service .dds request.")

    mr = DdsRequest(dispatcher, rpath)
    yield from mr.process()
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
        yield from _process_axon_grok(mr)
    elif req.startswith("/axon/read/"):
        # Render an individual Axon.
        yield from _process_axon_read(dispatcher, req[11:])
    elif req.startswith("/axon/synapses/"):
        # Scan for and render SynapseS connected to the requested Axon.
        yield from _process_axon_synapses(mr)
    elif req.startswith("/synapse/create/"):
        # Render the Create Synapse entry form.
        yield from _process_synapse_create(mr)
    elif req.startswith("/propedit/"):
        yield from _process_propedit(mr)
    else:
        dispatcher.send_error("request: {}".format(req), errcode=400)

@asyncio.coroutine
def serve_post(dispatcher, rpath):
    assert rpath.startswith(S_DDS)

    log.info("Service .dds post.")

    mr = DdsRequest(dispatcher, rpath)
    req = mr.req

    if req == "/synapse/create":
        yield from _process_synapse_create_post(dispatcher, req)
    elif req == "/feed/add":
        yield from _process_feed_add_post(mr)
    elif req == "/propedit":
        yield from _process_propedit_post(mr)
    else:
        dispatcher.send_error("request: {}".format(req), errcode=400)

@asyncio.coroutine
def _process_root(req):
    channel_html = yield from _render_channel_html(req)

    template = templates.dds_main[0]
    template = template.format(\
        csrf_token=req.dispatcher.client_engine.csrf_token,
        refresh_url="morphis://" + req.rpath,
        channels=channel_html,\
        query=req.query,\
        current_ident=req.ident_enc)

    available_idents = yield from dmail.render_dmail_addresses(\
        req.dispatcher, req.ident, use_key_as_id=True)

    template2 = templates.dds_identbar[0]
    template2 = template2.format(\
        current_ident=req.ident_enc, available_idents=available_idents)

    template = template2 + template

    wrapper = templates.dds_wrapper[0]
    wrapper =\
        wrapper.format(title="MORPHiS Maalstroom DDS", child=template)

    req.dispatcher.send_content(wrapper)

@asyncio.coroutine
def _process_propedit(req):
    rstr = req.req[10:]
    p1 = rstr.find('/')
    if p1 == -1:
        addr_enc = rstr
        path = ""
    else:
        addr_enc = rstr[:p1]
        path = rstr[p1+1:]

    addr = mbase32.decode(addr_enc)

    data_rw = yield from req.dispatcher.node.engine.tasks.send_get_data(\
        addr, path=path, force_cache=True)

    if data_rw and data_rw.data:
        value = data_rw.data.decode()
    else:
        value = ""

    refresh_url =\
        "morphis://.dds/propedit/{}/{}{}".format(addr_enc, path, req.query)

    template = templates.dds_propedit[0]
    template = template.format(\
        csrf_token=req.dispatcher.client_engine.csrf_token,
        refresh_url=refresh_url,\
        addr=addr_enc,\
        path=path,\
        version=data_rw.version,\
        value=value)

    wrapper = templates.dds_wrapper[0]
    wrapper =\
        wrapper.format(title="MORPHiS Propedit", child=template)

    req.dispatcher.send_content(wrapper)

@asyncio.coroutine
def _render_channel_html(req, ul_class=None):
    def dbcall():
        with req.dispatcher.node.db.open_session(True) as sess:
            r = sess.query(NodeState)\
                .filter(NodeState.key == DEFAULT_FEED_KEY)\
                .first()

            return r.value if r else None

    # Load user's channel list from the database.
    channels_json =\
        yield from req.dispatcher.loop.run_in_executor(None, dbcall)

    if channels_json:
        channels_list = json.loads(channels_json)
    else:
        channels_list =\
            ["$OWN", None,\
            "@MORPHiS", "@MORPHiS-dev", None,\
            "@news", "@tech-news", None,\
            "@math", "@math-proofs", None,\
            "@bitcoin", "@bitcoin-wizards", "@bitcoin-dev", None,\
            "$RANDOM"]

        def dbcall():
            with req.dispatcher.node.db.open_session() as sess:
                ns = NodeState()
                ns.key = DEFAULT_FEED_KEY
                ns.value = json.dumps(channels_list)
                sess.add(ns)
                sess.commit()

        yield from req.dispatcher.loop.run_in_executor(None, dbcall)

    if ul_class:
        channel_html = "<ul class='{}'>".format(ul_class)
    else:
        channel_html = "<ul>"

    for channel_row in channels_list:
        if channel_row is None:
            channel_html += "<br/>"
            continue

        if type(channel_row) is str:
            addr_enc = text = channel_row
        else:
            addr_enc = channel_row[0]
            text = channel_row[1] if len(channel_row) > 1 else addr_enc

        if addr_enc == "$RANDOM":
            addr_enc = mbase32.encode(os.urandom(consts.NODE_ID_BYTES))
        elif addr_enc == "$OWN":
            addr_enc = req.ident_enc

            name = yield from fetch_display_name(\
                req.dispatcher.node, req.ident, req.ident_enc)
            text = name + "'s Blog"

        channel_html +=\
            "<li><a href='morphis://.grok/{}{}'>{}</a></li>"\
                .format(addr_enc, req.query, text)

    channel_html += "</ul>"

    return channel_html

@asyncio.coroutine
def _process_axon_create(dispatcher, req):
    template = templates.dds_axon[0]
    template = template.format(\
        message_text="",
        csrf_token=dispatcher.client_engine.csrf_token,
        delete_class="display_none")

    dispatcher.send_content([template, req])

@asyncio.coroutine
def _process_axon_grok(req):
    arg = req.req[11:]

    if arg.startswith("@"):
        key = DdsEngine.calc_key_for_channel(arg[1:])
        channel_bare = arg[1:]
        arg = '#' + channel_bare
        significant_bits = None
    else:
        key, significant_bits = req.dispatcher.decode_key(arg)
        channel_bare = arg

        if not key:
            req.dispatcher.send_error(\
                "Invalid encoded key: [{}].".format(arg), 400)
            return

    if significant_bits:
        # Support prefix keys.
        key = yield from req.dispatcher.fetch_key(key, significant_bits)

        if not key:
            return

    username = yield from\
        fetch_display_name(req.dispatcher.node, req.ident, req.ident_enc)

    channel_html = yield from _render_channel_html(req, "dds-channel-submenu")

    data_rw = yield from req.dispatcher.node.engine.tasks.send_get_data(\
        key, path="title", force_cache=True)

    if data_rw and data_rw.data:
        title = data_rw.data.decode()
    else:
        title = channel_bare


    template = templates.dds_axon_grok[0]
    template = template.format(\
        key=mbase32.encode(key),\
        query=req.query,\
        user=username,\
        channel=arg,\
        channel_bare=title,\
        channel_html=channel_html)

    req.dispatcher.send_content(template)
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

    dds_engine = DdsEngine(dispatcher.node)
    post = yield from dds_engine.load_post(key)
    if not post:
        post = yield from dds_engine.fetch_post(key, target_key)

    if not post:
        dispatcher.send_content("Not found on the network at the moment.")
        return

    key_enc = mbase32.encode(key)

    content = yield from _format_axon(dispatcher.node, post.data, key, key_enc)

    timestr = mutil.format_human_no_ms_datetime(post.timestamp)

    template = templates.dds_synapse_view[0]
    template = template.format(\
        key=key_enc,\
        signing_key="",\
        signer="<TODO>",\
        content=content,\
        timestamp=timestr,\
        relative_time=mutil.format_datetime_as_relative(post.timestamp),\
        score=post.score)

    msg = "<head><link rel='stylesheet' href='morphis://.dds/style.css'>"\
        "</link></head><body style='height: 80%; padding:0;margin:0;'>{}"\
        "</body>"\
            .format(template)

    content_type = "text/html; charset={}"\
        .format(dispatcher.get_accept_charset())

    dispatcher.send_content(msg, content_type=content_type)
    return

@asyncio.coroutine
def _process_axon_synapses(req):
    axon_addr = mbase32.decode(req.req[15:])

    style = "background-color: red" if axon_addr == req.ident == axon_addr\
        else ""

    template = templates.dds_axon_synapses_start[0]\
        .format(style=style)

    req.dispatcher.send_partial_content(template, True)

    loaded = {}

    @asyncio.coroutine
    def process_post(post):
        assert type(post) is DdsPost

        key = post.synapse_key
        if not key:
            key = post.data_key

        if not post:
            if log.isEnabledFor(logging.INFO):
                log.info(\
                    "Post data not found for found key [{}]."\
                        .format(mbase32.encode(key)))
            return

        key_enc = mbase32.encode(key)

        content = yield from _format_axon(\
            req.dispatcher.node, post.data, key, key_enc)

        timestr = mutil.format_human_no_ms_datetime(post.timestamp)

        signing_key = post.signing_key if post.signing_key else ""
        signing_key_enc = mbase32.encode(post.signing_key)

        signer_name = yield from fetch_display_name(\
            req.dispatcher.node, signing_key, signing_key_enc)

        if post.signing_key == req.ident:
            style = "background-color: lightblue"
        elif post.signing_key == axon_addr:
            style = "background-color: yellow"
        else:
            style = ""

        target_key_enc = mbase32.encode(post.target_key)

        if post.target_key != axon_addr:
            target_str = "@" + target_key_enc
        else:
            target_str = ""

        template = templates.dds_synapse_view[0]
        template =\
            template.format(\
                target_key=target_key_enc,\
                target_str=target_str,\
                key=key_enc,\
                signing_key=signing_key_enc,\
                signer=signer_name,\
                content=content,\
                timestamp=timestr,\
                relative_time=\
                    mutil.format_datetime_as_relative(post.timestamp),\
                score=post.score,\
                style=style)

        req.dispatcher.send_partial_content(template)

    def dbcall():
        with req.dispatcher.node.db.open_session(True) as sess:
            q = sess.query(DdsPost)\
                .filter(\
                    or_(\
                        DdsPost.target_key == axon_addr,
                        DdsPost.signing_key == axon_addr))\
                .order_by(\
                    desc(and_(\
                        DdsPost.signing_key != None,\
                        DdsPost.signing_key == DdsPost.target_key)),\
                    DdsPost.timestamp)

            return q.all()

    posts = yield from req.dispatcher.loop.run_in_executor(None, dbcall)

    for post in posts:
        key = post.synapse_pow if post.synapse_pow else post.data_key
        loaded.setdefault(key, True)
        yield from process_post(post)

    req.dispatcher.send_partial_content(\
        "<div class='dds-refresh-wrapper'><hr id='new' class='style2'/>")

#    dds_engine = DdsEngine(dispatcher.node)
#    yield from dispatcher.client_engine.dds.dds_engine.scan_target_key(\
#        axon_addr, process_post)

    query = DdsQuery(axon_addr)
    already = req.dispatcher.client_engine.dds.check_query_autoscan(query)
    if not already:
        req.dispatcher.client_engine.dds.enable_query_autoscan(query)

        req.dispatcher.send_partial_content(\
            "<div>Started scanning for new messages...</div>"\
            "<span id='end' style='color: gray'/></body></html>"\
                .format(mutil.utc_datetime()))

        req.dispatcher.end_partial_content()
        return

#        # If this channel was not being scanned, then we will wait this first
#        # time.
#        all_done = asyncio.Event()
#
#        @asyncio.coroutine
#        def query_listener(post):
#            if post:
#                yield from process_post(post)
#            else:
#                all_done.set()
#
#        req.dispatcher.client_engine.dds.add_query_listener(\
#            query, query_listener)
#
#        yield from all_done.wait()

    req.dispatcher.send_partial_content(\
        "<div class='dds-refresh-text'>Last refreshed: {}</div><span id='end' style='color: gray'/></div>"\
        "</body></html>"\
            .format(mutil.utc_datetime()))

    req.dispatcher.end_partial_content()

@asyncio.coroutine
def fetch_display_name(node, signing_key, signing_key_enc=None):
    signer_name =\
        yield from dmail.get_contact_name(node, signing_key)

    if signing_key:
        if not signing_key_enc:
            signing_key_enc = mbase32.encode(signing_key)
        if signer_name == signing_key_enc:
            data_rw = yield from node.engine.tasks.send_get_data(\
                    signing_key, force_cache=True)

            if data_rw:
                json_bytes = data_rw.data
                if json_bytes:
                    name = json.loads(json_bytes.decode()).get("name")
                    if name:
                        signer_name = make_safe_for_html_content(name)
                        log.info("Using Dsite name=[{}] for key=[{}]."\
                            .format(signer_name, signing_key_enc))

    return signer_name

@asyncio.coroutine
def _process_synapse_create(req):
    target_addr = req.req[16:]
    if req.dispatcher.handle_cache(target_addr):
        return

    ident_name =\
        yield from dmail.get_contact_name(req.dispatcher.node, req.ident)
    if ident_name == req.ident_enc or not req.ident:
        ident_str = ident_name
    else:
        ident_str = "{} ({})".format(ident_name, req.ident_enc)

    template = templates.dds_create_synapse[0]
    template = template.format(\
        csrf_token=req.dispatcher.client_engine.csrf_token,\
        message_text="",\
        target_addr=target_addr,\
        ident=req.ident_enc,\
        ident_str=ident_str,\
        query=req.query)

#    template =\
#        templates.dds_wrapper[0].format(title="DDS Post Box", child=template)

    req.dispatcher.send_content(template)

@asyncio.coroutine
def _process_synapse_create_post(dispatcher, req):
    dd = yield from dispatcher.read_post()
    if not dd:
        dispatcher.send_error("request: {}".format(req), errcode=400)
        return

    if not dispatcher.check_csrf_token(dd["csrf_token"][0]):
        return

#    content = fia(dd["content"])
    content = None
    content2 = fia(dd.get("content2"))

    if not content:
        content = content2
    elif content2:
        content = content + "\r\n" + content2

    if not content:
        dispatcher.send_error("No content.", errcode=400)
        return

    content_key = None
    content_key_ready = asyncio.Event()

    def key_callback(akey):
        nonlocal content_key

        content_key = akey
        content_key_ready.set()

        if log.isEnabledFor(logging.INFO):
            log.info("content_key=[{}].".format(mbase32.encode(content_key)))

    @asyncio.coroutine
    def store_content():
        storing_nodes = 0
        for retry in range(10, 50, 5):
            storing_nodes += yield from\
                dispatcher.node.chord_engine.tasks.send_store_data(\
                    content.encode(),\
                    store_key=True,\
                    key_callback=key_callback,\
                    retry_factor=retry)

            if storing_nodes >= 5:
                if log.isEnabledFor(logging.INFO):
                    log.info("Stored content; storing_nodes=[{}]."\
                        .format(storing_nodes))
                break

        return storing_nodes

    content_task = asyncio.async(store_content(), loop=dispatcher.loop)

    yield from content_key_ready.wait()

    target_addr = fia(dd["target_addr"])

    if not target_addr:
        resp =\
            "Resulting&nbsp;<a href='morphis://.dds/axon/read/{axon_addr}'>"\
                "Axon</a>&nbsp;Address:<br/>{axon_addr}"\
                     .format(axon_addr=mbase32.encode(content_key))

        dispatcher.send_content(resp)
        return

    target_addr = mbase32.decode(target_addr)

    synapse = syn.Synapse.for_target(target_addr, content_key)

    ident_enc = fia(dd["ident"])
    if ident_enc:
        ident_addr = mbase32.decode(ident_enc)
        ident_dmail_address = yield from\
            dmail.load_dmail_address(dispatcher.node, site_key=ident_addr)
        signing_key =\
            rsakey.RsaKey(privdata=ident_dmail_address.site_privatekey)
        synapse.key = signing_key

    yield from dispatcher.node.engine.tasks.send_store_synapse(synapse)

    storing_nodes =\
        yield from asyncio.wait_for(content_task, None, loop=dispatcher.loop)

    if storing_nodes < 5:
        log.warning(\
            "Only [{}] storing nodes for content.".format(storing_nodes))

    resp =\
        "Resulting&nbsp;<a href='morphis://.dds/axon/read/{synapse_addr}/"\
            "{target_addr}'>Synapse</a>&nbsp;Address:<br/>{synapse_addr}"\
                 .format(\
                    synapse_addr=mbase32.encode(synapse.synapse_pow),\
                    target_addr=mbase32.encode(target_addr))

    dispatcher.send_content(resp)

@asyncio.coroutine
def _process_feed_add_post(req):
    dd = yield from req.dispatcher.read_post()

    if not req.dispatcher.check_csrf_token(dd["csrf_token"][0]):
        return

    refresh_url = fia(dd.get("refresh_url"))

    name = fia(dd.get("name"))
    address = fia(dd.get("address"))

    def dbcall():
        with req.dispatcher.node.db.open_session() as sess:
            feed = sess.query(NodeState)\
                .filter(NodeState.key == DEFAULT_FEED_KEY)\
                .first()

            if feed:
                feed_list = json.loads(feed.value)
            else:
                feed = NodeState()
                sess.add(feed)
                feed_list = []

            if not name and not address:
                feed_list.append(None)
            else:
                feed_list.append([address, name])

            feed.value = json.dumps(feed_list)

            sess.commit()

    req.dispatcher.loop.run_in_executor(None, dbcall)

    req.dispatcher.send_301(refresh_url)

@asyncio.coroutine
def _process_propedit_post(req):
    dd = yield from req.dispatcher.read_post()

    if not req.dispatcher.check_csrf_token(dd["csrf_token"][0]):
        return

    addr_enc = dd.get("addr")[0]
    addr = mbase32.decode(addr_enc)
    path = dd.get("path")[0]

    refresh_url = fia(dd.get("refresh_url"))
    value = fia(dd.get("value"))
    prev_value = fia(dd.get("previous_value"))

    if prev_value == value:
        if log.isEnabledFor(logging.INFO):
            log.info("No difference was submitted, ignoring POST.")
        req.dispatcher.send_301(refresh_url)
        return

    if log.isEnabledFor(logging.INFO):
        log.info("Updating value of key/path [{}]/[{}], len(value)=[{}]."\
            .format(addr_enc, path, len(value)))

    dm =\
        yield from dmail.load_dmail_address(req.dispatcher.node, site_key=addr)

    yield from req.dispatcher.node.engine.tasks.send_store_updateable_key(\
        value.encode(), rsakey.RsaKey(privdata=dm.site_privatekey),\
        path.encode(), int(time.time()*1000), store_key=True)

    req.dispatcher.send_301(refresh_url)

@asyncio.coroutine
def _format_axon(node, data, key, key_enc=None):
    result = __format_post(data)

    if not key_enc:
        key_enc = mbase32.encode(key)

    return result\
        + "<div style='float: right; font-family: monospace; font-style: italic; font-size: 8pt;"\
            "color: #a2a6ab; position: absolute; top: .6em; width: 100px; overflow: hidden;"\
            "text-overflow: ellipsis; -o-text-overflow: ellipsis; white-space: nowrap;"\
            "padding-right: 10px; padding-bottom: 5px; right: 0.3em;'>#{}</div>".format(key_enc[:32])

def __format_post(data):
    fr = data.find(b'\r')
    fn = data.find(b'\n')

    if fr == -1 and fn == -1:
        return "{}".format(make_safe_for_html_content(data))

    if fr == -1:
        end = fn
        start = end + 1
    elif fn == -1:
        end = fr
        start = end + 1
    else:
        end = fr
        start = end + 2

    return "{}<br/>" \
        "{}"\
            .format(\
                data[:end].decode(), make_safe_for_html_content(data[start:]))
