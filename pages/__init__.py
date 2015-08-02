# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

## Templates:
home_page_content = [\
    b"""<!DOCTYPE html>
<html><head><title>MORPHiS Maalstroom UI</title>
<link rel="stylesheet" type="text/css" href="morphis://.dmail/css"/>
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
<p><h2 style="display: inline;">MORPHiS Maalstroom UI</h2><span style="position: absolute; right: 0em;">(<a href="morphis://.aiwj/explanation">AIWJ</a> - JAVASCRIPT FREE!)</span></p>
<div class="msection">
    <h3>MORPHiS Web</h3>
    <p>
        <a href="morphis://3syweaeb7xwm4q3hxfp9w4nynhcnuob6r1mhj19ntu4gikjr7nhypezti4t1kacp4eyy3hcbxdbm4ria5bayb4rrfsafkscbik7c5ue/">MORPHiS Homepage</a><br/>
        <a href="morphis://3syweaeb7xwm4q3hxfp9w4nynhcnuob6r1mhj19ntu4gikjr7nhypezti4t1kacp4eyy3hcbxdbm4ria5bayb4rrfsafkscbik7c5ue/firefox_plugin">MORPHiS Firefox Plugin</a><br/>
    </p>
</div>
<div class="msection">
    <h3>MORPHiS Interface</h3>
    <p>
        <a href="morphis://.upload">Upload</a> (Upload data to the network.)<br/>
        <a href="morphis://.dmail">Dmail</a> (Encrypted Uncensorable Messaging!)<br/>
    </p>
</div>
</body></html>""", None]

dmail_css_content = [\
    b"""* {
    box-sizing: border-box;
}
html, body {
    height: 100%;
    padding: 0;
    margin: 0;
}
body.iframe {
    height: 0%;
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
.formfield * {
    vertical-align: top;
}
label:after {
    content: ": ";
}
iframe.panel {
    background-color: #86CBD2;
}
body.panel {
    display: table;
    height: 100%;
}
body.panel div.panel {
    display: table-cell;
    vertical-align: middle;
    height: 100%;
    padding-right: 0.75em;
    padding-left: 0.75em;
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
        <span><- <a href="morphis://">MORPHiS UI</a></span>
        <span id="footer_right">
            <span>[<a href="morphis://.dmail">List Dmail Addresses</a>]</span>
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
<html><head><base target="_root" /><link rel="stylesheet" type="text/css" href="morphis://.dmail/css"/></head><body class="iframe">
"""

dmail_frame_end =\
    b"""</body></html>"""

dmail_page_content__f1_start =\
    b"""<!DOCTYPE html>
<html><head><base target="_root" /><link rel="stylesheet" type="text/css" href="morphis://.dmail/css"/></head><body class="iframe">
<h4>Your dmail addresses:</h4>
"""

dmail_page_content__f1_end =\
    b"""</body></html>"""

dmail_address_page_content = [None, None]

dmail_inbox_start =\
    b"""<!DOCTYPE html>
<html><head><base target="_root" /><link rel="stylesheet" type="text/css" href="morphis://.dmail/css"/></head><body class="iframe">
<h4>Dmails for address [<a href="../../addr/${DMAIL_ADDRESS}">${DMAIL_ADDRESS2}</a>]:</h4>
"""

dmail_inbox_end =\
    b"""</body></html>"""

dmail_addr_view_start =\
    b"""<!DOCTYPE html>
<html><head><base target="_root" /><link rel="stylesheet" type="text/css" href="morphis://.dmail/css"/>
<style type="text/css">
</style></head><body class="iframe">
<p class="nomargin">
    <a href="/tag/view/Inbox/${DMAIL_ADDRESS}">View Inbox</a>
    [<a href="/scan/${DMAIL_ADDRESS}">Scan Network for New Messages</a>]
</p>
"""

dmail_addr_view_end =\
    b"""</body></html>"""

dmail_tag_view_content = [None, None]

dmail_tag_view_list_start =\
    b"""<!DOCTYPE html>
<html><head><base target="_root" /><link rel="stylesheet" type="text/css" href="morphis://.dmail/css"/></head><body class="iframe">
<h4>Dmails for tag [${TAG_NAME}] of address [<a href="../../../../addr/${DMAIL_ADDRESS}">${DMAIL_ADDRESS2}</a>]:</h4>
"""

dmail_tag_view_list_end =\
    b"""</body></html>"""

dmail_fetch_wrapper = [\
    b"""<!DOCTYPE html>
<html><head><base target="_root" /><link rel="stylesheet" type="text/css" href="morphis://.dmail/css"/></head><body>
<iframe src="${IFRAME_SRC}" frameborder="0" style="height: calc(100% - 2em);" width="100%"></iframe>
<iframe src="${IFRAME2_SRC}" class="panel" frameborder="0" style="height: 2em;" width="100%"></iframe>
</body></html>""", None]

dmail_fetch_panel_content = [\
    b"""<!DOCTYPE html>
<html><head><base target="_root" /><link rel="stylesheet" type="text/css" href="morphis://.dmail/css"/></head><body class="iframe panel">
<div class="panel">
    <span>
        [<a target="_self" href="../mark_as_read/${DMAIL_IDS}">Toggle Read</a>]
    </span><span>
        [<a target="_self" href="../trash/${DMAIL_IDS}">Trash Dmail</a>]
    </span>
</div>
</body></html>""", None]

dmail_create_address_content = [None, None]

dmail_create_address_form_content = [\
    b"""<!DOCTYPE html>
<html><head><base target="_root" /><link rel="stylesheet" type="text/css" href="morphis://.dmail/css"/></head><body class="iframe">
<form action="make_it_so" method="get">
    <label for="prefix">Dmail Prefix</label>
    <input type="textfield" name="prefix" id="prefix"/>
    <p style="font-style: italic;">(Optional: Each letter in the prefix will make the address take 32x longer to generate.)</p>
    <p style="font-style: italic;">(Three letters takes almost an hour on my test machine.)</p>
    <input type="submit" formtarget="_self" id="create" value="Create"/>
</form>
</body></html>""", None]

dmail_compose_dmail_content = [None, None]

dmail_compose_dmail_form_start =\
    b"""<!DOCTYPE html>
<html><head><base target="_root" /><link rel="stylesheet" type="text/css" href="morphis://.dmail/css"/>
<style type="text/css">
</style></head><body class="iframe">
<form action="make_it_so" method="post">
    <p class="formfield">
        <label for="sender">From</label>
        <select name="sender">"""

dmail_compose_dmail_form_end =\
    b"""</select>
    </p><p class="formfield">
        <label for="destination">To</label>
        <input type="textfield" name="destination" id="destination" size="70" value="${DEST_ADDR}"/>
    </p><p class="formfield">
        <label for="subject">Subject</label>
        <input type="textfield" name="subject" id="subject" size="70"/>
    </p><p class="formfield">
        <label for="content">Message Content</label>
        <textarea name="content" id="content" cols="80" rows="24"></textarea>
    </p>
    <input type="submit" formtarget="_self" id="send" value="Send"/> (This will take at least a few seconds, if not much longer, depending on the difficulty (anti-spam setting) set by the owner of the destination address.)
</form>
</body></html>"""

##.

initialized_template = False
if not initialized_template:
    dmail_page_content[0] =\
        dmail_page_wrapper.replace(b"${IFRAME_SRC}", b"address_list")

    dmail_address_page_content[0] = dmail_page_wrapper

    dmail_create_address_content[0] =\
        dmail_page_wrapper.replace(b"${IFRAME_SRC}", b"create_address/form")

    dmail_compose_dmail_content[0] = dmail_page_wrapper

    dmail_tag_view_content[0] = dmail_page_wrapper

    initialized_template = True
