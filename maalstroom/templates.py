# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import logging
import os
import threading

log = logging.getLogger(__name__)

## Templates:
home_page_content = [\
    b"""<!DOCTYPE html>
<html><head><title>ALL TOGETHER NOW WE SING IN UNISON - MORPHiS Maalstroom UI</title>
<link rel="icon" type="image/png" href="/.images/favicon.ico"/>
<link rel="stylesheet" type="text/css" href="morphis://.main/style.css"/>
<style type="text/css">
    div.msection {
        border-width 2px;
        border: dashed;
        padding: 1em; margin-top: 1em;
    }
    body {
        position: absolute;
        top: 0;
        width: 100%;
    }
</style>
</head><body>
<div class="valign_container header_non_fs"><h2 style="display: inline;">MORPHiS Maalstroom UI</h2><span class="valign"><span class="h-3">&nbsp;&nbsp;&nbsp;[v${MORPHIS_VERSION}]&nbsp;[${CONNECTIONS} Connections]</span><span class="right_float"><span class="h-3 bold" style="margin: 0;">(<a href="morphis://.aiwj/explanation">AIWJ</a> - JAVASCRIPT FREE!)</span></span></div>
<div class="msection">
    <h3>MORPHiS Web</h3>
    <p>
        <a href="morphis://sp1nara3xhndtgswh7fznt414we4mi3y6kdwbkz4jmt8ocb6x4w1faqjotjkcrefta11swe3h53dt6oru3r13t667pr7cpe3ocxeuma">Official MORPHiS ???Site! (need new word here :)</a><br/>
        <hr/>

        <a href="morphis://sp1nara3xhndtgswh7fznt414we4mi3y6kdwbkz4jmt8ocb6x4w1faqjotjkcrefta11swe3h53dt6oru3r13t667pr7cpe3ocxeuma/webmirror">MORPHiS Mirror of MORPHiS' Stone Age Web-site :)</a><br/>
        <a href="morphis://sp1nara3xhndtgswh7fznt414we4mi3y6kdwbkz4jmt8ocb6x4w1faqjotjkcrefta11swe3h53dt6oru3r13t667pr7cpe3ocxeuma/firefox_plugin">MORPHiS Firefox Plugin</a><br/>
    </p>
</div>
<div class="msection">
    <h3>MORPHiS Interface</h3>
    <p>
        <a href="morphis://.upload/">Upload</a> (Upload data to the network.)<br/>
        <a href="morphis://.dmail/">Dmail</a> (Encrypted Uncensorable Messaging!)<br/>
        <a href="morphis://.dds/">DDS</a> (Distributed Discussion System)<br/>
    </p>
</div>
</body></html>""", None]

favicon_content = [None, None]

dmail_css_content = [\
    b"""* {
    box-sizing: border-box;
}
html, body {
    height: 100%;
    padding: 0;
    margin: 0;
}
.right_float {
    position: fixed;
    right: 0em;
}
.h-1 {
    font-size: 95%;
}
.h-2 {
    font-size: 85%;
}
.h-3 {
    font-size: 75%;
}
body.iframe {
    height: 0%;
}
div.header_non_fs {
    margin-top: 1em;
}
div.header {
    height: 3em;
    padding: 0;
    margin: 0;
    /* FIXME:
       Disgustingly enough (CSS is so), having the border fixes everything.
       We don't actually want a border, so we make it invisible with the
       color. Let this be proof that MORPHiS must deprecate CSS at
       somepoint as well! :) */
    border: solid 1px; /* Doesn't mater as long as not 0 or hidden. */
    border-color: #ffffff #ffffff; /* Invisible without browser knowing. */
}
div.footer {
    height: 3em;
    width: 100%;
    padding: 1em;
    margin: 0;
    bottom: 0px;
    position: absolute;
}
div.section {
    height: calc(100% - 7em);
    border: dashed 0.2em;
    margin-top: 1em;
    padding: 1em;
}
h4 {
    margin: 0 0 1em 0;
    padding: 0;
}
h5 {
    margin: 0;
    padding: 0;
}
div * * span {
    margin-left: 0.5em;
    margin-right: 0.5em;
}
#footer_right {
    right: 0px;
    position: absolute;
}
.nomargin {
    margin: 0;
}
iframe {
    margin: 0;
    margin-bottom: -4px; //FIXME: SOMEONE DEPRECATE HTML/CSS FOR ME PLEASE!
    // Without the above hack there is extra padding after an iframe, breaking
    // calcs and making scrollbars where there shouldn't be.
    padding: 0;
}
label {
    width: 10em;
    display: inline-block;
    text-align: right;
}
form p * {
    vertical-align: top;
}
label:after {
    content: ": ";
}
.valign_container {
    display: table;
}
.valign_container .valign {
    display: table-cell;
    vertical-align: middle;
    height: 100%;
}
body.panel_container {
    background-color: #86CBD2;
    display: table;
    height: 100%;
}
.panel_container .panel {
    display: table-cell;
    vertical-align: middle;
    height: 100%;
    padding-right: 0.75em;
    padding-left: 0.75em;
}
.italic {
    font-style: italic;
}
.bold {
    font-weight: bold;
}
.strikethrough {
    text-decoration: line-through;
}
div.panel span {
    padding-right: 0.25em;
    padding-left: 0.25em;
}
.right_text {
    position: absolute;
    right: 0;
}
.nowrap {
    white-space: nowrap;
}
.tag {
    background-color: #EEEEFF;
}
""", None]

dmail_page_wrapper =\
    b"""<!DOCTYPE html>
<html><head><title>MORPHiS Maalstroom Dmail Client</title>
<link rel="stylesheet" type="text/css" href="morphis://.dmail/css"/>
</head><body>
<div class="header">
    <h2>MORPHiS Maalstroom Dmail Client</h2>
</div>
<div class="footer">
    <h5>
        <span>&lt;- <a href="morphis://">MORPHiS UI</a></span>
        <span id="footer_right">
            <span>[<a href="morphis://.dmail/">List Dmail Addresses</a>]</span>
            <span>[<a href="morphis://.dmail/create_address">Create New Dmail Address</a>]</span>
            <span>[<a href="morphis://.dmail/compose">Send a Dmail</a>]</span>
        </span>
    </h5>
</div>
<div class="section">
    <iframe src="${IFRAME_SRC}" frameborder="0" height="100%" width="100%"></iframe>
</div>
</body></html>"""

dmail_page_content = [None, None]

dmail_frame_start =\
    b"""<!DOCTYPE html>
<html><head><base target="_top" /><link rel="stylesheet" type="text/css" href="morphis://.dmail/css"/></head><body class="iframe">
"""

dmail_frame_end =\
    b"""</body></html>"""

dmail_page_content__f1_start =\
    b"""<!DOCTYPE html>
<html><head><base target="_top" /><link rel="stylesheet" type="text/css" href="morphis://.dmail/style.css"/></head><body class="iframe">
<h4>Your dmail addresses:</h4>
"""

dmail_page_content__f1_end =\
    b"""</body></html>"""

dmail_address_page_content = [None, None]

dmail_inbox_start =\
    b"""<!DOCTYPE html>
<html><head><base target="_top" /><link rel="stylesheet" type="text/css" href="morphis://.dmail/css"/></head><body class="iframe">
<h4>Dmails for address [<a href="../../addr/${DMAIL_ADDRESS}">${DMAIL_ADDRESS2}</a>]:</h4>
"""

dmail_inbox_end =\
    b"""</body></html>"""

dmail_addr_view_start =\
    b"""<!DOCTYPE html>
<html><head><base target="_top" /><link rel="stylesheet" type="text/css" href="morphis://.dmail/css"/>
<style type="text/css">
</style></head><body class="iframe">
<h4>Dmail Address [${DMAIL_ADDRESS_SHORT}...].</h4>
<p class="nomargin">
    <a href="../../tag/view/Inbox/${DMAIL_ADDRESS}">View Inbox</a>
    [<a href="../../scan/${DMAIL_ADDRESS}">Scan Network for New Messages</a>]
</p>
<p>
    [<a href="../settings/${DMAIL_ADDRESS}">Address Settings</a>]
</p>
"""

dmail_addr_view_end =\
    b"""</body></html>"""

dmail_addr_settings_content = [None, None]

dmail_iframe_body_start =\
    b"""<!DOCTYPE html>
<html><head><base target="_top" /><link rel="stylesheet" type="text/css" href="morphis://.dmail/css"/></head><body class="iframe">"""

dmail_addr_settings_edit_success_content = [dmail_iframe_body_start.decode()\
    + """<h4>Dmail Address [<a target="_top" href="morphis://.dmail/wrapper/{}">{}...</a>].</h4><p>SUCCESS.</p></body></html>""", None]

dmail_addr_settings_edit_fail_content = [dmail_iframe_body_start.decode()\
    + """<h4>Dmail Address [<a target="_top" href="morphis://.dmail/wrapper/{}">{}...</a>].</h4><p>FAIL.</p><p>Try again in a bit.</p></body></html>""", None]

dmail_tag_view_content = [None, None]

dmail_tag_view_list_start =\
    b"""<!DOCTYPE html>
<html><head><base target="_top" /><link rel="stylesheet" type="text/css" href="morphis://.dmail/css"/></head><body class="iframe">
<h4>Dmails for tag [${TAG_NAME}] of address [<a href="../../../../addr/${DMAIL_ADDRESS}">${DMAIL_ADDRESS2}</a>]:</h4>
"""

dmail_tag_view_list_end =\
    b"""</body></html>"""

dmail_fetch_wrapper = [\
    b"""<!DOCTYPE html>
<html><head><base target="_top" /><link rel="stylesheet" type="text/css" href="morphis://.dmail/css"/></head><body>
<iframe src="${IFRAME_SRC}" frameborder="0" style="height: calc(100% - 2em);" width="100%"></iframe>
<iframe src="${IFRAME2_SRC}" frameborder="0" style="height: 2em;" width="100%"></iframe>
</body></html>""", None]

dmail_fetch_panel_content = [\
    b"""<!DOCTYPE html>
<html><head><base target="_top" /><link rel="stylesheet" type="text/css" href="morphis://.dmail/css"/></head><body class="iframe panel_container">
<div class="panel">
    <span>
        [<a target="_self" href="../mark_as_read/${DMAIL_IDS}">Toggle Read</a>]
    </span><span>
        [<a target="_self" href="../trash/${DMAIL_IDS}">Trash Dmail</a>]
    </span>
</div>
</body></html>""", None]

dmail_create_address_content = [None, None]

dmail_compose_dmail_content = [None, None]

dmail_compose_dmail_form_start =\
    b"""<!DOCTYPE html>
<html><head><base target="_top" /><link rel="stylesheet" type="text/css" href="morphis://.dmail/css"/>
<style type="text/css">
</style></head><body class="iframe">
<form action="morphis://.dmail/compose/make_it_so" method="post" accept-charset="UTF-8 ISO-8859-1">
    <p class="nowrap">
        <label for="sender">From</label>
        <select name="sender">"""

dmail_compose_dmail_form_end =\
    b"""</select>
    </p><p>
        <label for="destination">To</label>
        <input type="textfield" name="destination" id="destination" size="70" value="${DEST_ADDR}"/>
    </p><p>
        <label for="subject">Subject</label>
        <input type="textfield" name="subject" id="subject" size="70"/>
    </p><p>
        <label for="content">Message Content</label>
        <textarea name="content" id="content" cols="80" rows="24"></textarea>
    </p>
    <input type="submit" formtarget="_self" id="send" value="Send"/> (This will take at least a few seconds, if not much longer, depending on the difficulty (anti-spam setting) set by the owner of the destination address. Also, there is randomness involved.)
</form>
</body></html>"""

##.

initialized_template = False
if not initialized_template:
    fh = open("favicon.ico", "rb")
    if fh:
        favicon_content[0] = fh.read()

    dmail_page_content[0] =\
        dmail_page_wrapper.replace(b"${IFRAME_SRC}", b"address_list")

    dmail_address_page_content[0] = dmail_page_wrapper

    dmail_addr_settings_content[0] = dmail_page_wrapper

    dmail_create_address_content[0] =\
        dmail_page_wrapper.replace(b"${IFRAME_SRC}", b"create_address/form")

    dmail_compose_dmail_content[0] = dmail_page_wrapper

    dmail_tag_view_content[0] = dmail_page_wrapper

def load(filepath, dynamic=False):
    fh = open("maalstroom/templates/" + filepath, "rb")
    template = fh.read()
    if dynamic:
        template = template.decode()
    return [template, None]

_resource_type_mapping = {\
    "css": "text/css",\
    "png": "image/png",\
    "jpg": "image/jpeg",\
    "jpeg": "image/jpeg",\
    "gif": "image/gif"}

def load_resource(filepath):
    fh = open("maalstroom/resources/" + filepath, "rb")
    ext = filepath[filepath.rindex('.')+1:]
    return [fh.read(), None, _resource_type_mapping[ext]]

def load_resources(store, dirpath):
    for entry_name in os.listdir("maalstroom/resources/" + dirpath):
        if log.isEnabledFor(logging.DEBUG):
            log.debug("Loading resource [{}][{}]."\
                .format(dirpath, entry_name))

        store[entry_name] = load_resource(dirpath + "/" + entry_name)

dmail_imgs = {}
dds_imgs = {}

if not initialized_template:
    # V2 UI:
    main_css = dmail_css_content 

    main_combined_upload = load("main/combined_upload.html", True)

    dmail_css = load_resource("style.css")

    dmail_page_wrapper = load("dmail/page_wrapper.html", True)
    dmail_logo = load("dmail/logo.html", True)
    dmail_nav = load("dmail/nav.html", True)
    dmail_aside = load("dmail/aside.html", True)

    dmail_msg_list = load("dmail/msg_list.html", True)
    dmail_msg_list_list_start = load("dmail/msg_list_list_start.html", True)
    dmail_msg_list_list_row = load("dmail/msg_list_list_row.html", True)
    dmail_msg_list_list_end = load("dmail/msg_list_list_end.html")
    dmail_new_mail = load("dmail/new_mail.html", True)
    dmail_read = load("dmail/read.html", True)
    dmail_compose = load("dmail/compose.html", True)
    dmail_address_list = load("dmail/address_list.html", True)
    dmail_address_list_row = load("dmail/address_list_row.html", True)

    dmail_create_address = load("dmail/create_address.html", True)
    dmail_address_config = load("dmail/address_config.html", True)

    dmail_addressbook_create_contact =\
        load("dmail/addressbook_create_contact.html", True)
    dmail_addressbook_list_start =\
        load("dmail/addressbook_list_start.html", True)
    dmail_addressbook_list_row = load("dmail/addressbook_list_row.html", True)
    dmail_addressbook_list_end = load("dmail/addressbook_list_end.html", True)
    dmail_addressbook_rename_contact =\
        load("dmail/addressbook_rename_contact.html",True)

    dmail_post_msg_and_link = load("dmail/post_msg_and_link.html", True)

    load_resources(dmail_imgs, "images/dmail")

    # dds.
    dds_css = load("dds/style.css", True)

    dds_wrapper = load("dds/wrapper.html", True)

    dds_identbar = load("dds/identbar.html", True)

    dds_main = load("dds/main.html", True)
    dds_axon = load("dds/axon.html", True)
    dds_create_synapse = load("dds/create_synapse.html", True)
    dds_axon_synapses_start = load("dds/axon_synapses_start.html", True)
    dds_synapse_view = load("dds/synapse_view.html", True)

    load_resources(dds_imgs, "images/dds")

    initialized_template = True
