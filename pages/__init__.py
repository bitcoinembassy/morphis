# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

## Templates:
home_page_content = [\
    b"""<!DOCTYPE html>
<html><head><title>MORPHiS Maalstroom UI</title>
<style type="text/css">
    div.section { border-width 2px; border: dashed; padding: 1em; margin-top: 1em; }
</style>
</head><body>
<p><h2>MORPHiS Maalstroom UI</h2></p>
<div class="section">
    <h3>MORPHiS Web</h3>
    <p>
        <a href="morphis://3syweaeb7xwm4q3hxfp9w4nynhcnuob6r1mhj19ntu4gikjr7nhypezti4t1kacp4eyy3hcbxdbm4ria5bayb4rrfsafkscbik7c5ue/">MORPHiS Homepage</a><br/>
        <a href="morphis://3syweaeb7xwm4q3hxfp9w4nynhcnuob6r1mhj19ntu4gikjr7nhypezti4t1kacp4eyy3hcbxdbm4ria5bayb4rrfsafkscbik7c5ue/firefox_plugin">MORPHiS Firefox Plugin</a><br/>
    </p>
</div>
<div class="section">
    <h3>MORPHiS Interface</h3>
    <p>
        <a href="morphis://.upload">Upload</a> (Upload data to the network.)<br/>
        <a href="morphis://.dmail">Dmail</a> (Encrypted Uncensorable Messaging!)<br/>
    </p>
</div>
</body></html>""", None]

dmail_page_wrapper =\
    b"""<!DOCTYPE html>
<html><head><title>MORPHiS Maalstroom Dmail Client</title>
<style type="text/css">
    * {
        box-sizing: border-box;
    }
    html, body { 
        height: 100%;
        padding: 0;
        margin: 0;
    }
    div.header {
        height: 3em;
        padding: 0;
        margin: 0;
        /* Disgustingly enough (CSS is so), having the border fixes everything.
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
    h5 {
        margin: 0;
        padding: 0;
    }
</style>
</head><body>
<div class="header">
    <h2>MORPHiS Maalstroom Dmail Client</h2>
</div>
<div class="footer">
    <h5><- <a href="morphis://">MORPHiS UI</a></h5>
</div>
<div class="section">
    <iframe src="${IFRAME_SRC}" frameborder="0" height="100%" width="100%"/>
</div>
</body></html>"""

dmail_page_content = [None, None]

dmail_page_content__f1_start =\
    b"""<!DOCTYPE html>
<html><head><base target="_parent" /></head><body>
<h4>Your dmail addresses:</h4>
"""

dmail_page_content__f1_end =\
    b"""</body></html>"""

dmail_address_page_content = [None, None]

dmail_inbox_start =\
    b"""<!DOCTYPE html>
<html><head><base target="_parent" /></head><body>
<h4>Dmails for address [${DMAIL_ADDRESS}]:</h4>
"""

dmail_inbox_end =\
    b"""</body></html>"""

##.

initialized_template = False
if not initialized_template:
    dmail_page_content[0] =\
        dmail_page_wrapper.replace(b"${IFRAME_SRC}", b"address_list")

    dmail_address_page_content[0] = dmail_page_wrapper

    initialized_template = True
