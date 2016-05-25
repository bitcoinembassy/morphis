#!/usr/bin/python3
# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import argparse
import asyncio
import logging
import os
from sys import stdin

import base58
import client
import db
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

    log.info("mget running.")

    parser = argparse.ArgumentParser()
    parser.add_argument(\
        "--address",\
        help="The address of the Morphis node to connect to.",\
        default="127.0.0.1:4250")
    parser.add_argument(\
        "--dburl",\
        help="Specify the database url to use.")
    parser.add_argument("--nn", type=int,\
        help="Node instance number.")
    parser.add_argument("-l", dest="logconf",\
        help="Specify alternate logging.ini [IF SPECIFIED, THIS MUST BE THE"\
            " FIRST PARAMETER!].")

    parser.add_argument("key", type=str)

    parser.add_argument(\
        "-i",\
        help="Read file as stdin.")
    parser.add_argument(\
        "-o",\
        help="Send output to specified file.",
        type=str)

    parser.add_argument(\
        "--stat",\
        help="Report node status.",\
        action="store_true")

    args = parser.parse_args()

    # Load or generate client mcc key.
    key_filename = "data/mget_key-rsa.mnk"
    if os.path.exists(key_filename):
        log.info("mget private key file found, loading.")
        client_key = rsakey.RsaKey(filename=key_filename)
    else:
        log.info("mget private key file missing, generating.")
        client_key = rsakey.RsaKey.generate(bits=4096)
        client_key.write_private_key_file(key_filename)

    # Connect a Morphis Client (lightweight Node) instance.
    mc = client.Client(loop, client_key=client_key, address=args.address)
    r = yield from mc.connect()

    if not r:
        log.warning("Connection failed; exiting.")
        loop.stop()
        return

#    dbase = init_db(args)

    yield from __process(args, loop, mc)

    # Finished request, clean up.
    log.info("Disconnecting.")
    yield from mc.disconnect()

    loop.stop()

@asyncio.coroutine
def __process(args, loop, mc):
    log.info("Processing command requests...")

    if args.stat:
        r = yield from mc.send_command("stat")
        llog.printl(r.decode("UTF-8"))
        return

    # Process the request (for now, we support send_get_data(..) requests.
    key, sig_bits = mutil.decode_key(args.key)

    if sig_bits:
        data_rw = yield from mc.send_find_key(key, sig_bits)
        key = data_rw.data_key
        if not key:
            log.error("Key [{}] was not found.".format(args.key))
            return

    data_rw = yield from mc.send_get_data(key)

    if not data_rw.data:
        log.error(\
            "Data for key [{}] was not found.".format(mbase32.encode(key)))
        return

    if args.o:
        # Write to a file instead of stdout.
        f = open(args.o, "wb")
        f.write(data_rw.data)
    else:
        # Write the response to stdout.
        print(data_rw.data.decode())

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
