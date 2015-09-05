# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import argparse
import asyncio
import logging
import os
from sys import stdin

import base58
import brute
import client
import db
import dmail
import enc
import mbase32
import mutil
import rsakey
import sshtype

log = logging.getLogger(__name__)

def main():
    global loop

    loop = asyncio.get_event_loop()

    asyncio.async(_main(), loop=loop)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        log.info("Got KeyboardInterrupt; shutting down.")
    except Exception:
        log.exception("loop.run_forever()")

    log.info("Shutdown.")

@asyncio.coroutine
def _main():
    global loop

    try:
        yield from __main()
    except BaseException as e:
        if type(e) is not SystemExit:
            log.exception("__main()")
        loop.stop()

@asyncio.coroutine
def __main():
    global loop

    log.info("mcc running.")

    parser = argparse.ArgumentParser()
    parser.add_argument(\
        "--address",\
        help="The address of the Morphis node to connect to.",\
        default="127.0.0.1:4250")
    parser.add_argument(\
        "--create-dmail",\
        help="Generate and upload a new dmail site.",\
        action="store_true")
    parser.add_argument(\
        "--dburl",\
        help="Specify the database url to use.")
    parser.add_argument(\
        "--fetch-dmail",
        help="Fetch dmail for specified key_id.")
    parser.add_argument(\
        "-i",\
        help="Read file as stdin.")
    parser.add_argument("--nn", type=int,\
        help="Node instance number.")
    parser.add_argument(\
        "--prefix",\
        help="Specify the prefix for various things (currently --create-dmail"\
            ").")
    parser.add_argument(\
        "--scan-dmail",\
        help="Scan the network for available dmails.")
    parser.add_argument(\
        "--send-dmail",\
        help="Send stdin as a dmail with the specified subject. The"\
            " sender and recipients may be specified at the beginning of the"\
            " data as with email headers: 'from: ' and 'to: '.")
    parser.add_argument(\
        "--stat",\
        help="Report node status.",\
        action="store_true")
    parser.add_argument("-l", dest="logconf",\
        help="Specify alternate logging.ini [IF SPECIFIED, THIS MUST BE THE"\
            " FIRST PARAMETER!].")
    parser.add_argument(\
        "--dmail-target",\
        help="Specify the dmail target to validate dmail against.")
    parser.add_argument(\
        "-x",\
        help="Specify the x (Diffie-Hellman private secret) to use.")

    args = parser.parse_args()

    # Load or generate client mcc key.
    key_filename = "data/mcc_key-rsa.mnk"
    if os.path.exists(key_filename):
        log.info("mcc private key file found, loading.")
        client_key = rsakey.RsaKey(filename=key_filename)
    else:
        log.info("mcc private key file missing, generating.")
        client_key = rsakey.RsaKey.generate(bits=4096)
        client_key.write_private_key_file(key_filename)

    # Connect a Morphis Client (lightweight Node) instance.
    mc = client.Client(loop, client_key=client_key, address=args.address)
    r = yield from mc.connect()

    if not r:
        log.warning("Connection failed; exiting.")
        loop.stop()
        return

    dbase = init_db(args)
    de = dmail.DmailEngine(mc, dbase)

    log.info("Processing command requests...")

    if args.stat:
        r = yield from mc.send_command("stat")
        print(r.decode("UTF-8"), end='')

    if args.create_dmail:
        log.info("Creating and uploading dmail site.")

        privkey, data_key, dms, storing_nodes =\
            yield from de.generate_dmail_address(args.prefix)

        print("privkey: {}".format(base58.encode(privkey._encode_key())))
        print("x: {}".format(base58.encode(sshtype.encodeMpint(dms.dh.x))))
        print("dmail address: {}".format(mbase32.encode(data_key)))
        print("storing_nodes=[{}]."\
            .format(base58.encode(privkey._encode_key())))

    if args.send_dmail:
        log.info("Sending dmail.")

        if args.i:
            with open(args.i, "rb") as fh:
                dmail_data = fh.read().decode()
        else:
            dmail_data = stdin.read()

        if log.isEnabledFor(logging.DEBUG):
            log.debug("dmail_data=[{}].".format(dmail_data))

        yield from de.send_dmail_text(args.send_dmail, dmail_data)

    if args.scan_dmail:
        log.info("Scanning dmail address.")

        addr, sig_bits = mutil.decode_key(args.scan_dmail)

        def key_callback(key):
            print("dmail key: [{}].".format(mbase32.encode(key)))

        yield from de.scan_dmail_address(\
            addr, sig_bits, key_callback=key_callback)

    if args.fetch_dmail:
        log.info("Fetching dmail for key=[{}].".format(args.fetch_dmail))

        key = mbase32.decode(args.fetch_dmail)

        if args.x:
            l, x_int = sshtype.parseMpint(base58.decode(args.x))
        else:
            x_int = None

        dmail_target = mbase32.decode(args.dmail_target)

        dm, valid_sig =\
            yield from de.fetch_dmail(key, x_int, dmail_target)

        if not dm:
            raise Exception("No dmail found.")

        if not x_int:
            print("Encrypted dmail data=[\n{}].".format(mutil.hex_dump(dm)))
        else:
            print("Subject: {}\n".format(dm.subject))

            if valid_sig:
                print("Valid Signature.")
            else:
                print("INVALID Signature.")

            if dm.sender_pubkey:
                print("From: {}"\
                    .format(mbase32.encode(enc.generate_ID(dm.sender_pubkey))))

            if dm.version >= 2:
                print("To: " + mbase32.encode(dm.destination_addr))

            i = 0
            for part in dm.parts:
                print("DmailPart[{}]:\n    mime-type=[{}]\n    data=[{}]\n"\
                    .format(i, part.mime_type, part.data))
                i += 1

    log.info("Disconnecting.")

    yield from mc.disconnect()

    loop.stop()

def init_db(args):
    if args.dburl:
        if args.nn:
            dbase = db.Db(loop, args.dburl, 'n' + str(args.nn))
        else:
            dbase = db.Db(loop, args.dburl)
    else:
        if args.nn:
            dbase = db.Db(loop, "sqlite:///data/morphis-{}.sqlite"\
                .format(args.nn))
        else:
            dbase = db.Db(loop, "sqlite:///data/morphis.sqlite")

    dbase.init_engine()

    return dbase

if __name__ == "__main__":
    main()
