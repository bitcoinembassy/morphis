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

from sqlalchemy import and_, desc, func, literal, or_
from sqlalchemy.orm import joinedload, aliased
from sqlalchemy.exc import ResourceClosedError

import consts
from db import User, DdsPost, DdsStamp, NodeState, sqlalchemy_pre_1_0_15
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
import synapse
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

    def check_csrf_token(self):
        return self.dispatcher.check_csrf_token(fia(\
            self.qdict.get("csrf_token")))

    @property
    def csrf_query_element(self):
        return "&csrf_token=" + self.dispatcher.client_engine.csrf_token

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
        yield from _process_axon_create(mr)
    elif req.startswith("/axon/grok/"):
        # Render the Grok View; which shows the Axon, SynapseS and Synapse
        # create form.
        yield from _process_axon_grok(mr)
#    elif req.startswith("/axon/read/"):
#        # Render an individual Axon.
#        yield from _process_axon_read(dispatcher, req[11:])
    elif req.startswith("/axon/synapses/"):
        # Scan for and render SynapseS connected to the requested Axon.
        yield from _process_axon_synapses(mr)
    elif req.startswith("/synapse/create/"):
        # Render the Create Synapse entry form.
        yield from _process_synapse_create(mr)
    elif req.startswith("/stamp/synapse/"):
        yield from _process_stamp_synapse(mr)
    elif req.startswith("/stamp/signer/"):
        yield from _process_stamp_signer(mr)
    elif req.startswith("/propedit/"):
        yield from _process_propedit(mr)
    elif req.startswith("/site/edit/"):
        yield from _process_site_edit(mr)
    elif req.startswith("/test/"):
        yield from _process_test(mr)
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
    elif req == "/site/edit":
        yield from _process_site_edit_post(mr)
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

    wrapper =\
        yield from _render_wrapper(req, template, "MORPHiS Maalstroom DDS")

    req.dispatcher.send_content(wrapper)

@asyncio.coroutine
def _render_wrapper(req, template, title="MORPHiS Maalstroom DDS"):
    channel_html =\
        yield from _render_channel_html(req, "dashboard-convo-list", True)

    current_version = req.dispatcher.node.morphis_version
    latest_version_number = req.dispatcher.latest_version_number

    if latest_version_number\
            and current_version != latest_version_number:
        version_str =\
            '<span class="dds-strikethrough">{}</span>'\
            '&nbsp;[<a href="{}{}">New Version: {}</a>]'\
                .format(current_version,\
                    req.dispatcher.handler.maalstroom_url_prefix_str,\
                    "sp1nara3xhndtgswh7fznt414we4mi3y6kdwbkz4jmt8ocb6"\
                        "x4w1faqjotjkcrefta11swe3h53dt6oru3r13t667pr7"\
                        "cpe3ocxeuma/latest_version",\
                    latest_version_number)
    else:
        version_str = current_version

    connections = req.dispatcher.connection_count
    if connections == 1:
        connection_str = "1 Connection"
    else:
        connection_str = str(connections) + " Connections"

    return templates.dds_wrapper[0].format(\
        node_version=version_str,\
        node_connections=connection_str,\
        channel_html=channel_html,\
        child=template,\
        query=req.query,\
        current_ident=req.ident_enc,\
        title=title)

@asyncio.coroutine
def _process_test(req):
    #TODO: Delete this test stub.
    rstr = req.req[6:]

    req.dispatcher.send_content("rstr=[{}].".format(rstr))

@asyncio.coroutine
def _render_axon_grok_config(req):
    local_name =\
        yield from dmail.get_contact_name(req.dispatcher.node, req.ident)
    public_name =\
        yield from fetch_display_name(\
            req.dispatcher.node, req.ident, addr_fallback=True)

    stamped = yield from _render_stamped(req, req.ident)
    if not stamped:
        stamped = "No stamped keys found."

    stampers = yield from _render_stampers(req, req.ident)
    if not stampers:
        stampers = "No stamping keys found."

    return templates.dds_axon_config[0].format(\
        ident=req.ident_enc,\
        local_name=local_name,\
        public_name=public_name,\
        stamped=stamped,\
        stampers=stampers)

@asyncio.coroutine
def _render_stamped(req, key):
    def dbcall():
        with req.dispatcher.node.db.open_session(True) as sess:
            return\
                sess.query(DdsStamp).filter(DdsStamp.signing_key == key).all()

    stamps = yield from req.dispatcher.loop.run_in_executor(None, dbcall)

    if not stamps:
        return None

    return (yield from _render_stamps(req, stamps))

@asyncio.coroutine
def _render_stampers(req, key):
    def dbcall():
        with req.dispatcher.node.db.open_session(True) as sess:
            return\
                sess.query(DdsStamp).filter(DdsStamp.signed_key == key).all()

    stamps = yield from req.dispatcher.loop.run_in_executor(None, dbcall)

    if not stamps:
        return None

    return (yield from _render_stamps(req, stamps))

@asyncio.coroutine
def _render_stamps(req, stamps):
    out = []

    for stamp in stamps:
        signing_name = yield from fetch_display_name(\
            req.dispatcher.node, stamp.signing_key)
        if signing_name:
            signing_name = "{} ({})".format(\
                signing_name, mbase32.encode(stamp.signing_key))
        else:
            signing_name = mbase32.encode(stamp.signing_key)

        signed_name = yield from fetch_display_name(\
            req.dispatcher.node, stamp.signed_key)
        if signed_name:
            signed_name = "{} ({})".format(\
                signed_name, mbase32.encode(stamp.signed_key))
        else:
            signed_name = mbase32.encode(stamp.signed_key)

        out.append(templates.dds_stamp[0].format(\
            signing_name=signing_name,\
            version=stamp.version,\
            signed_name=signed_name))

    return ''.join(out)

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
        csrf_token=req.dispatcher.client_engine.csrf_token,\
        refresh_url=refresh_url,\
        addr=addr_enc,\
        path=path,\
        version=data_rw.version,\
        value=value)

    wrapper = yield from _render_wrapper(req, template, "MORPHiS Propedit")

    req.dispatcher.send_content(wrapper)

@asyncio.coroutine
def _process_site_edit(req):
    rstr = req.req[11:]

    addr_enc = rstr
    addr = mbase32.decode(addr_enc)

    te = req.dispatcher.node.engine.tasks

#    timeout = 0.25

    props = (\
        "title", "image", "anon_name", "min_unsigned_pow", "min_unstamped_pow")

    tasks = []

    for prop in props:
        tasks.append(\
#            asyncio.wait_for(\
                te.send_get_data(addr, prop, force_cache=True))#, timeout))

    results = yield from asyncio.gather(*tasks, return_exceptions=True)

    out = {}
    latest_version = 0

    for result, prop in zip(results, props):
        if not result or isinstance(result, Exception) or not result.data:
            out[prop] = ""
        else:
            if result.version > latest_version:
                latest_version = result.version
            out[prop] = result.data.decode()

    refresh_url =\
        "morphis://.dds/site/edit/{}{}".format(addr_enc, req.query)

    template = templates.dds_site_edit[0]
    template = template.format(\
        csrf_token=req.dispatcher.client_engine.csrf_token,\
        refresh_url=refresh_url,\
        addr=addr_enc,\
        version=latest_version,\
        **out)

    wrapper = yield from _render_wrapper(req, template, "MORPHiS Siteedit")

    req.dispatcher.send_content(wrapper)

@asyncio.coroutine
def _process_site_edit_post(req):
    dd = yield from req.dispatcher.read_post()

    if not req.dispatcher.check_csrf_token(dd["csrf_token"][0]):
        return

    addr_enc = dd.get("addr")[0]
    addr = mbase32.decode(addr_enc)
    refresh_url = dd.get("refresh_url")[0]

    # Load in the private key for signing any updates.
    dm =\
        yield from dmail.load_dmail_address(req.dispatcher.node, site_key=addr)
    key = rsakey.RsaKey(privdata=dm.site_privatekey)

    props = (\
        "title", "image", "anon_name", "min_unsigned_pow", "min_unstamped_pow")

    version = int(time.time()*1000)

    te = req.dispatcher.node.engine.tasks

    @asyncio.coroutine
    def task(prop):
        value = dd.get(prop)[0]

        data_rw = yield from te.send_get_data(addr, prop, force_cache=True)
        if data_rw and data_rw.data:
            old = data_rw.data.decode()
            if not old:
                old = ""
        else:
            old = ""

        if old == value:
            if log.isEnabledFor(logging.INFO):
                log.info(\
                    "No difference was submitted for key/path [{}]/[{}]."\
                        .format(addr_enc, prop))
            return

        if log.isEnabledFor(logging.INFO):
            log.info("Updating key/path [{}]/[{}] value to [{}]."\
                .format(addr_enc, prop, value))

        yield from te.send_store_updateable_key(\
            value.encode(), key, prop.encode(), version, store_key=True)

        if log.isEnabledFor(logging.INFO):
            log.info("Key/path [{}]/[{}] updated.".format(addr_enc, prop))

    yield from asyncio.gather(*[task(prop) for prop in props])

    req.dispatcher.send_301(refresh_url)

@asyncio.coroutine
def _render_channel_html(req, ul_class=None, site_nav=False):
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

    nav = "#site-nav" if site_nav else ""

    for channel_row in channels_list:
        if channel_row is None:
            channel_html += "<br/>"
            continue

        clazz = "dashboard-icon-chat-group"

        if type(channel_row) is str:
            addr_enc = channel_row
            text = addr_enc[1:]
        else:
            addr_enc = channel_row[0]
            text = channel_row[1] if len(channel_row) > 1 else addr_enc

        if addr_enc == "$RANDOM":
            addr_enc = mbase32.encode(os.urandom(consts.NODE_ID_BYTES))
            text = "$RANDOM"
        elif addr_enc == "$OWN":
            addr_enc = req.ident_enc

            name = yield from fetch_display_name(\
                req.dispatcher.node, req.ident, req.ident_enc,\
                addr_fallback=True)
            text = name + "'s Blog"
            clazz = "dashboard-icon-chat-blog"

        channel_html +=\
            "<li class='{} dds-trunc'>"\
            "<a href='morphis://.grok/{}{}{}'>{}</a></li>"\
                .format(clazz, addr_enc, req.query, nav, text)

    channel_html += "</ul>"

    return channel_html

@asyncio.coroutine
def _process_axon_create(req):
    template = templates.dds_axon[0]
    template = template.format(\
        message_text="",
        csrf_token=req.dispatcher.client_engine.csrf_token,
        delete_class="display_none")

    wrapper = yield from _render_wrapper(req, template, "MORPHiS Axon Create")

    req.dispatcher.send_content(wrapper)

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
        fetch_display_name(\
            req.dispatcher.node, req.ident, req.ident_enc, addr_fallback=True)

    channel_html = yield from _render_channel_html(req, "dds-channel-submenu")

    #FIXME: Temporarily add a timeout until the cache caches NULL responses.
    try:
        data_rw = yield from asyncio.wait_for(\
            req.dispatcher.node.engine.tasks.send_get_data(\
                key, path="title", force_cache=True),\
            0.25)
    except futures.TimeoutError as e:
        data_rw = None

    if data_rw and data_rw.data:
        title = data_rw.data.decode()
    else:
        title = channel_bare

    template = templates.dds_axon_grok[0]
    template = template.format(\
        key=mbase32.encode(key),\
        query=req.query,\
        settings_html=(yield from _render_axon_grok_config(req)),\
        user=username,\
        channel=arg,\
        channel_bare=title,\
        channel_html=channel_html)

    wrapper =\
        yield from _render_wrapper(req, template, "MORPHiS Maalstroom DDS")

    req.dispatcher.send_content(wrapper)
    return

#@asyncio.coroutine
#def _process_axon_read(dispatcher, req):
#    p0 = req.find('/')
#
#    if p0 > -1:
#        # Then the request is for a TargetedBlock.
#        key = mbase32.decode(req[:p0])
#        target_key = mbase32.decode(req[p0+1:])
#    else:
#        # Then the request is not for a TargetedBlock.
#        key = mbase32.decode(req)
#        target_key = None
#
#    dds_engine = DdsEngine(dispatcher.node)
#    post = yield from dds_engine.load_post(key)
#    if not post:
#        post = yield from dds_engine.fetch_post(key, target_key)
#
#    if not post:
#        dispatcher.send_content("Not found on the network at the moment.")
#        return
#
#    key_enc = mbase32.encode(key)
#
#    content = yield from _format_axon(dispatcher.node, post.data, key, key_enc)
#
#    timestr = mutil.format_human_no_ms_datetime(post.timestamp)
#
#    template = templates.dds_synapse_view[0]
#    template = template.format(\
#        key=key_enc,\
#        signing_key="",\
#        signer="<TODO>",\
#        content=content,\
#        timestamp=timestr,\
#        relative_time=mutil.format_datetime_as_relative(post.timestamp),\
#        score=post.score)
#
#    msg = "<head><link rel='stylesheet' href='morphis://.dds/style.css'>"\
#        "</link></head><body style='height: 80%; padding:0;margin:0;'>{}"\
#        "</body>"\
#            .format(template)
#
#    content_type = "text/html; charset={}"\
#        .format(dispatcher.get_accept_charset())
#
#    dispatcher.send_content(msg, content_type=content_type)
#    return

@asyncio.coroutine
def _process_axon_synapses(req):
    axon_addr_enc = req.req[15:]
    axon_addr = mbase32.decode(axon_addr_enc)

    te = req.dispatcher.node.engine.tasks

    timeout = 0.25

    props = (\
        "title", "image", "anon_name", "min_unsigned_pow", "min_unstamped_pow")

    gtask = asyncio.async(\
        asyncio.gather(*[\
            asyncio.wait_for(\
                asyncio.shield(
                    te.send_get_data(axon_addr, prop, force_cache=True)),\
                timeout)\
            for prop in props], return_exceptions=True))

    style = "background: url('morphis://.dds/images/sayagata-400px.png');"\
        " background-attachment: fixed;"\
            if axon_addr == req.ident == axon_addr else ""

    template = templates.dds_axon_synapses_start[0]\
        .format(style=style)

    req.dispatcher.send_partial_content(template, True)

    def dbcall():
        with req.dispatcher.node.db.open_session(True) as sess:
#                .options(joinedload("children"))\

            # Prepare recursive DdsStamp query.
            children = sess.query(\
                    DdsStamp,\
                    literal(0).label("deep"),\
                    DdsStamp.signing_key.label("source"))\
                .filter(or_(\
                    DdsStamp.signing_key == axon_addr,\
                    DdsStamp.signing_key == req.ident))\
                .cte(name="children", recursive=True)

            sta = aliased(DdsStamp, name="stamp")

            if sqlalchemy_pre_1_0_15:
                ra = aliased(children, name="root")
            else:
                ra = children

            children = children.union_all(\
                sess.query(\
                        sta,\
                        ra.c.deep.op("+")(1).label("deep"),\
                        ra.c.source)\
                    .join(ra, sta.signing_key == ra.c.signed_key)\
                    .filter(ra.c.deep < 7))

            #TODO: Optimize by putting some if statements to not do both
            # subqueries when axon_addr == req.ident.

            # The following func.min(..) causes the group-wise minimum to be
            # selected. (This was tested for Sqlite3, have to test and or fix
            # for PostgreSQL.)
            axon_stamp = sess.query(\
                    children.c.signing_key,\
                    children.c.signed_key,\
                    func.min(children.c.deep))\
                .select_from(children).group_by(children.c.signed_key)\
                .filter(children.c.source == axon_addr)\
                .subquery()

            self_stamp = sess.query(\
                    children.c.signing_key,\
                    children.c.signed_key,\
                    func.min(children.c.deep))\
                .select_from(children).group_by(children.c.signed_key)\
                .filter(children.c.source == req.ident)\
                .subquery()

            self_stamp2 = aliased(self_stamp)

            #rs = sess.query(children).all()

            # Main DdsPost query.
            q = sess.query(\
                    DdsPost,\
                    axon_stamp.c.signing_key,\
                    self_stamp.c.signing_key,\
                    self_stamp2.c.signing_key)\
                .filter(or_(\
                    DdsPost.target_key == axon_addr,\
                    DdsPost.target_key2 == axon_addr,\
                    DdsPost.signing_key == axon_addr))\
                .outerjoin(\
                    axon_stamp,\
                    or_(\
                        axon_stamp.c.signed_key == DdsPost.synapse_key,\
                        axon_stamp.c.signed_key == DdsPost.signing_key))\
                .outerjoin(\
                    self_stamp,\
                    self_stamp.c.signed_key == DdsPost.synapse_key)\
                .outerjoin(\
                    self_stamp2,\
                    self_stamp2.c.signed_key == DdsPost.signing_key)\
                .group_by(DdsPost.synapse_key)\
                .order_by(\
                    desc(and_(\
                        DdsPost.signing_key != None,\
                        DdsPost.signing_key == axon_addr,\
                        DdsPost.signing_key == DdsPost.target_key,\
                        DdsPost.target_key2 == None)),\
                    desc(or_(\
                        and_(\
                            DdsPost.target_key != axon_addr,\
                            DdsPost.target_key2 != axon_addr),\
                        and_(\
                            DdsPost.target_key != axon_addr,\
                            DdsPost.target_key2 == None))),\
                    DdsPost.timestamp)

            if log.isEnabledFor(logging.INFO):
                start = time.time()

            try:
                r = q.all()
            except ResourceClosedError as e:
                #FIXME: Workaround for bug http://bugs.python.org/issue21718.
                log.warning("FIXME: SqlAlchemy ResourceClosedError.")
                r = []

            if log.isEnabledFor(logging.INFO):
                log.info("Maalstroom DDS Grok CTE took [{:0.4f}] s."\
                    .format(time.time() - start))
                log.info("Loaded [{}] DdsPost entries.".format(len(r)))

            sess.expunge_all()

            return r

    load_task = req.dispatcher.loop.run_in_executor(None, dbcall)

    results, posts = yield from asyncio.gather(gtask, load_task)

    title, image, anon_name, min_unsigned_pow, min_unstamped_pow =\
        [result.data\
            if result and not isinstance(result, Exception) and result.data\
                else None for result in results]

    if anon_name:
        anon_name = make_safe_for_html_content(anon_name.decode())

    @asyncio.coroutine
    def process_post(post, axon_stamp, self_synapse_stamp, self_signer_stamp,\
            depth=0):
        assert type(post) is DdsPost, type(post)

        key = post.synapse_key
        if not key:
            key = post.data_key

        key_enc = mbase32.encode(key)

        content = make_safe_for_html_content(post.data)

        timestr = mutil.format_human_no_ms_datetime(post.timestamp)

        signing_key = post.signing_key if post.signing_key else ""
        signing_key_enc = mbase32.encode(post.signing_key)

        if signing_key or not anon_name:
            signer_name = yield from fetch_display_name(\
                req.dispatcher.node, signing_key, signing_key_enc,\
                addr_fallback=True)
        else:
            signer_name = anon_name

        if post.signing_key == axon_addr:
            # Post is by owner of axon.
            style = "box-shadow: 0 1px 4px rgba(0,0,0,.04); border: 1px solid"\
            " rgba(56, 163, 175,.3); border-radius: 5px; margin: 1em 1em;"\
            " background: #cyan;" # Blue tint.
        elif axon_stamp:
            # Post is authorized (by owner) to post in axon.
            style = "box-shadow: 0 1px 4px rgba(0,0,0,.04); border: 1px solid"\
            " rgba(56, 163, 175,.3); border-radius: 5px; margin: 1em 1em;"\
            " background: #FFFFFF;" # White.
        elif post.signing_key == req.ident:
            # Post is by us and not authorized to post in axon by the owner.
            style = "box-shadow: 0 1px 4px rgba(0,0,0,.04); border: 1px solid"\
            " rgba(163, 163, 163,.3); border-radius: 5px; margin: 1em 1em;"\
            " background: #fffc92;" # Gold..
        elif self_synapse_stamp or self_signer_stamp:
            # Post is by someone in our WOT but not authorized by axon owner.
            style = "box-shadow: 0 1px 4px rgba(0,0,0,.04); border: 1px solid"\
            " rgba(56, 163, 175,.3); border-radius: 5px; margin: 1em 1em;"\
            " background: #e6e384;" # Gold tint.
        elif post.signing_key and (not min_unstamped_pow\
                or post.score > int(min_unstamped_pow)):
            # Post is not in our WOT nor authorized by axon owner, but signed.
            style = "box-shadow: 0 1px 4px rgba(0,0,0,.04); border: 1px solid"\
            " rgba(56, 163, 175,.3); border-radius: 5px; margin: 1em 1em;"\
            " background: #e7f7f7;"
        elif not post.signing_key and (not min_unsigned_pow\
                or post.score > int(min_unsigned_pow)):
            # Post is not in our WOT nor authorized by axon owner, un-signed.
            style = "box-shadow: 0 1px 4px rgba(0,0,0,.04); border: 1px solid"\
            " rgba(56, 163, 175,.3); border-radius: 5px; margin: 1em 1em;"\
            " background: #d8e6e6;"
        else:
            # Post is not in our WOT, not authorized by owner, AND has below
            # required minimum proof of work to show up (so TODO: make this row
            # something like a collapsed css accordian trick).
            style = "background: gray; text-color: gray;"

        stamp_button_visibility = ""
        stamp_signer_visibility = ""
        stamp_synapse_visibility = ""

        if req.ident:
            if post.signing_key:
                if post.signing_key == req.ident:
                    # Don't stamp Synapse we signed ourselves.
                    stamp_button_visibility = "display: none;"
                else:
                    if self_signer_stamp == req.ident:
                        stamp_signer_visibility = "display: none;"
                    if self_synapse_stamp == req.ident:
                        stamp_synapse_visibility = "display: none;"
            else:
                if self_synapse_stamp == req.ident:
                    # Unsigned and we already stamped synapse_key.
                    stamp_button_visibility = "display: none;"
                else:
                    stamp_signer_visibility = "display: none;"
        else:
            stamp_button_visibility = "display: none;"

        target_key_enc = mbase32.encode(post.target_key)

        if post.target_key != axon_addr:
            target_str = "@" + target_key_enc
            if post.target_key2:
                target_key_link = "#" + target_key_enc
                target_key_link_target_attr = "target='_self'"
            else:
                target_key_link = "morphis://.dds/axon/grok/" + target_key_enc
                target_key_link_target_attr = "target='_parent'"
        else:
            target_str = ""
            target_key_link = ""
            target_key_link_target_attr = ""

#        if depth:
#            style += "margin-left: {}px;".format(depth * 50)

        if not post.target_key2\
                and post.signing_key == post.target_key == axon_addr:
            template = templates.dds_synapse_view_blog[0]
        else:
            template = templates.dds_synapse_view[0]

        template = template.format(\
            axon_addr=axon_addr_enc,\
            csrf=req.csrf_query_element,\
            query=req.query,\
            target_key=target_key_enc,\
            target_key_link=target_key_link,\
            target_key_link_target_attr=target_key_link_target_attr,\
            target_str=target_str,\
            key=key_enc,\
            signing_key=signing_key_enc,\
            signer=signer_name,\
            stamp_button_visibility=stamp_button_visibility,\
            stamp_signer_visibility=stamp_signer_visibility,\
            stamp_synapse_visibility=stamp_synapse_visibility,\
            content=content,\
            timestamp=timestr,\
            relative_time=\
                mutil.format_datetime_as_relative(post.timestamp),\
            score=post.score,\
            style=style)

        req.dispatcher.send_partial_content(template)

#        if not depth:
#            for post in post.children:
#                yield from process_post(post, depth=depth + 1)

    #TODO: Optimize by moving this into above gather.
    for row in posts:
        yield from process_post(*row)

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
def fetch_display_name(\
        node, signing_key, signing_key_enc=None, addr_fallback=False):
    if not signing_key:
        return "[Unsigned?]"

    signer_name =\
        yield from dmail._get_contact_name(node, signing_key)

    if not signer_name:
        data_rw = yield from node.engine.tasks.send_get_data(\
                signing_key, force_cache=True)

        if data_rw:
            json_bytes = data_rw.data
            if json_bytes:
                try:
                    name = json.loads(json_bytes.decode()).get("name")

                    if name:
                        signer_name = make_safe_for_html_content(name)
                        if log.isEnabledFor(logging.INFO):
                            log.info("Using Dsite name=[{}] for key=[{}]."\
                                .format(\
                                    signer_name, mbase32.encode(signing_key)))
                except Exception:
                    pass

    if not signer_name:
        return mbase32.encode(signing_key)

    return signer_name

@asyncio.coroutine
def _process_synapse_create(req):
    rstr = req.req[16:]
    p1 = rstr.find('/')
    if p1 == -1:
        target_addr_enc = rstr
        target_addr2_enc = ""
        reply_str = "Thinks:"
    else:
        target_addr_enc = rstr[:p1]
        target_addr2_enc = rstr[p1+1:]
        reply_str = "@{}".format(target_addr_enc)

    if req.dispatcher.handle_cache(target_addr_enc):
        return

    ident_name =\
        yield from dmail.get_contact_name(req.dispatcher.node, req.ident)
    if ident_name == req.ident_enc or not req.ident:
        ident_str = ident_name
    else:
        ident_str = "{} ({})".format(ident_name, req.ident_enc)

    template = templates.dds_synapse_create[0]
    template = template.format(\
        csrf_token=req.dispatcher.client_engine.csrf_token,\
        message_text="",\
        reply_str=reply_str,\
        target_addr=target_addr_enc,\
        target_addr2=target_addr2_enc,\
        ident=req.ident_enc,\
        ident_str=ident_str,\
        query=req.query)

    template = templates.dds_wrapper_lite[0].format(\
        title="DDS Post Box", child=template)

    req.dispatcher.send_content(template)

@asyncio.coroutine
def _process_stamp_synapse(req, stamp_signing_key=False):
    if not req.check_csrf_token():
        return

    if stamp_signing_key:
        rstr = req.req[14:]
    else:
        rstr = req.req[15:]

    synapse_key_enc, axon_addr_enc = rstr.split('/', 1)

    synapse_key = mbase32.decode(synapse_key_enc)
    if axon_addr_enc:
        axon_addr = mbase32.decode(axon_addr_enc)

    # Fetch Synapse object from the DHT.
    data_rw = yield from\
        req.dispatcher.node.engine.tasks.send_get_targeted_data(synapse_key)

    if not data_rw or not data_rw.data:
        req.dispatcher.send_error("No Synapse found.".format(req), errcode=400)
        return

    syn = data_rw.object

    if type(syn) is not synapse.Synapse:
        req.dispatcher.send_error("Not a Synapse.".format(req), errcode=400)
        return

    if stamp_signing_key:
        if not syn.is_signed():
            req.dispatcher.send_error(\
                "Not a signed Synapse.".format(req), errcode=400)
            return
        key_to_sign = syn.signing_key
    else:
        key_to_sign = syn.synapse_key

    # Load private key.
    ident_dmail_address = yield from dmail.load_dmail_address(\
        req.dispatcher.node, site_key=req.ident)

    our_signing_key =\
        rsakey.RsaKey(privdata=ident_dmail_address.site_privatekey)

    if log.isEnabledFor(logging.INFO):
        log.info("Stamping key=[{}].".format(mbase32.encode(key_to_sign)))

    # Create new stamp.
    syn.stamps = [synapse.Stamp(key_to_sign, our_signing_key)]

    yield from syn.encode()

    if axon_addr_enc and axon_addr != req.ident:
        if log.isEnabledFor(logging.INFO):
            log.info(\
                "Stamping Synapse while not axon owner, searching for path.")

        def dbcall():
            with req.dispatcher.node.db.open_session(True) as sess:
                # Prepare recursive DdsStamp query.
                children = sess.query(\
                        DdsStamp,\
                        literal(0).label("deep"),\
                        DdsStamp.id.label("trail"))\
                    .filter(DdsStamp.signing_key == axon_addr)\
                    .cte(name="children", recursive=True)

                sta = aliased(DdsStamp, name="stamp")

                if sqlalchemy_pre_1_0_15:
                    ra = aliased(children, name="root")
                else:
                    ra = children

                children = children.union_all(\
                    sess.query(\
                            sta,\
                            ra.c.deep.op("+")(1).label("deep"),\
                            ra.c.trail\
                                .concat(literal(","))\
                                .concat(sta.id)\
                                .label("trail"))\
                        .join(ra, sta.signing_key == ra.c.signed_key)\
                        .filter(ra.c.deep < 7))

                # The following func.min(..) causes the group-wise minimum to
                # be selected. (This was tested for Sqlite3, have to test and
                # or fix for PostgreSQL.)
                q = sess.query(\
                        children.c.trail,\
                        children.c.signed_key,\
                        func.min(children.c.deep))\
                    .select_from(children).group_by(children.c.signed_key)\
                    .filter(children.c.signed_key == req.ident)

                try:
                    r = q.one_or_none()
                except ResourceClosedError as e:
                    #FIXME: Workaround for bug
                    # http://bugs.python.org/issue21718.
                    log.warning("FIXME: SqlAlchemy ResourceClosedError.")
                    r = None

                if not r:
                    return None

                if log.isEnabledFor(logging.DEBUG):
                    log.debug("DdsStamp path query result: r[0]=[{}], r=[{}]."\
                        .format(r[0], r))

                path = r[0]

                if type(path) is str:
                    stamp_path = str(path.split(','))
                else:
                    # If it is one deep, SQLite returns int.
                    stamp_path = (str(path),)

                if log.isEnabledFor(logging.DEBUG):
                    log.debug("DdsStamp path=[{}].".format(stamp_path))

                stamps = sess.query(DdsStamp)\
                    .filter(DdsStamp.id.in_(stamp_path))\
                    .all()

                sess.expunge_all()

                return stamp_path, stamps

        stamp_path, db_stamps =\
            yield from req.dispatcher.loop.run_in_executor(None, dbcall)

        stamp_map = {stamp.id: stamp for stamp in db_stamps}
        db_stamps.clear()

        for i in range(len(stamp_path)-1, -1, -1):
            db_stamps.append(stamp_map[int(stamp_path[i])])

        if db_stamps:
            if log.isEnabledFor(logging.INFO):
                log.info("Found [{}] length Stamp path to axon_addr."\
                    .format(len(db_stamps)))
                if log.isEnabledFor(logging.DEBUG):
                    idx = 0
                    for db_stamp in db_stamps:
                        log.debug("db_stamp[{}].signing_key=[{}]."\
                            .format(idx, mbase32.encode(db_stamp.signing_key)))
                        idx += 1

            for db_stamp in db_stamps:
                # Fetch Stamp object from the DHT.
                data_rw = yield from\
                    req.dispatcher.node.engine.tasks.send_get_targeted_data(\
                        db_stamp.stamp_key)

                if not data_rw or not data_rw.data:
                    req.dispatcher.send_error(\
                        "Required Stamp in Stamp path was not found."\
                            .format(req),\
                        errcode=400)
                    return

                stamp = data_rw.object

                if log.isEnabledFor(logging.DEBUG):
                    log.debug("Found Stamp for path, signing_key=[{}]."\
                        .format(mbase32.encode(stamp.signing_key)))

                syn.stamps.append(stamp)

            if log.isEnabledFor(logging.DEBUG):
                idx = 0
                for stamp in syn.stamps:
                    log.debug("syn.stamp[{}].signing_key=[{}]."\
                        .format(idx, mbase32.encode(stamp.signing_key)))
                    idx += 1

            # Ensure that we have built a valid StampPed Synapse.
            syn.check_stamps()

            if log.isEnabledFor(logging.INFO):
                log.info("Synapse [{}] is now StampPed to axon_addr."\
                    .format(mbase32.encode(syn.synapse_key)))
        else:
            if log.isEnabledFor(logging.INFO):
                log.info("No known Stamp path from ident to axon_addr.")

    if log.isEnabledFor(logging.INFO):
        log.info("Uploading newly StampPed Synapse.")

    # Upload StampPed Synapse back to DHT.
    yield from req.dispatcher.node.engine.tasks.send_store_synapse(\
        syn, for_update=True)

    req.dispatcher.send_204()

@asyncio.coroutine
def _process_stamp_signer(req):
    return (yield from _process_stamp_synapse(req, True))

@asyncio.coroutine
def _process_synapse_create_post(dispatcher, req):
    dd = yield from dispatcher.read_post()
    if not dd:
        dispatcher.send_error("request: {}".format(req), errcode=400)
        return

    if not dispatcher.check_csrf_token(dd["csrf_token"][0]):
        return

    content = fia(dd["content"])

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

    target_addr_enc = fia(dd["target_addr"])
    target_addr2_enc = fia(dd["target_addr2"])

    if not target_addr_enc:
        resp =\
            "Resulting&nbsp;<a href='morphis://.dds/axon/read/{axon_addr}'>"\
                "Axon</a>&nbsp;Address:<br/>{axon_addr}"\
                     .format(axon_addr=mbase32.encode(content_key))

        dispatcher.send_content(resp)
        return

    if log.isEnabledFor(logging.INFO):
        log.info("Storing Synapse for content key [{}]."\
            .format(mbase32.encode(content_key)))

    target_addr = mbase32.decode(target_addr_enc)

    # Create a Synapse linking all the target keys.
    if not target_addr2_enc:
        syn = synapse.Synapse.for_target(target_addr, content_key)
    else:
        target_addr2 = mbase32.decode(target_addr2_enc)
        syn = synapse.Synapse.for_targets(\
            (target_addr, target_addr2), content_key)

    ident_enc = fia(dd["ident"])
    if ident_enc:
        ident_addr = mbase32.decode(ident_enc)
        ident_dmail_address = yield from\
            dmail.load_dmail_address(dispatcher.node, site_key=ident_addr)
        signing_key =\
            rsakey.RsaKey(privdata=ident_dmail_address.site_privatekey)
        syn.key = signing_key

    yield from dispatcher.node.engine.tasks.send_store_synapse(syn)

    storing_nodes =\
        yield from asyncio.wait_for(content_task, None, loop=dispatcher.loop)

    if log.isEnabledFor(logging.INFO):
        log.info("Stored Synapse (synapse_key=[{}]."\
            .format(mbase32.encode(syn.synapse_key)))

    if storing_nodes < 5:
        log.warning(\
            "Only [{}] storing nodes for content.".format(storing_nodes))

    resp =\
        "Resulting&nbsp;<a href='morphis://.dds/axon/read/{synapse_addr}/"\
            "{target_addr}'>Synapse</a>&nbsp;Address:<br/>{synapse_addr}"\
                 .format(\
                    synapse_addr=mbase32.encode(syn.synapse_key),\
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
