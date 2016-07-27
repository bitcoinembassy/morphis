#!/usr/bin/python3
# Copyright (c) 2014-2016  Sam Maloney.
# License: GPL v2.

import llog

import argparse
import asyncio
import logging
import os
import sys

import base58
import client
import db
import enc
import mbase32
import multipart
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
    parser.add_argument(\
        "--store-data", action="store_true",
        help="Store data in MORPHiS and return the key.")
    parser.add_argument(\
        "--nn", type=int,\
        help="Node instance number.")
    parser.add_argument(\
        "-l", dest="logconf",\
        help="Specify alternate logging.ini [IF SPECIFIED, THIS MUST BE THE"\
            " FIRST PARAMETER!].")

    parser.add_argument("key", type=str, nargs="?")

    parser.add_argument(\
        "-i",\
        help="Read file as stdin.")
    parser.add_argument(\
        "-o", type=str,\
        help="Send output to specified file.")
    parser.add_argument(\
        "-O", action="store_true",\
        help="Send output to specified file.")

    parser.add_argument(\
        "--stat", action="store_true",\
        help="Report node status.")

    parser.add_argument(\
        "-e", dest="encrypt", action="store_true",\
        help="Encrypt AES-256 in CBC mode using a random key.")

    args = parser.parse_args()

    # Load or generate client mcc key.
    key_filename = "data/mget_key-rsa.mnk"
    if os.path.exists(key_filename):
        log.info("mget private key file found, loading.")
        client_key = rsakey.RsaKey(filename=key_filename)
    else:
        log.info("mget private key file missing, generating.")
        if not os.path.exists("data"):
            os.mkdir("data")
        client_key = rsakey.RsaKey.generate(bits=4096)
        client_key.write_private_key_file(key_filename)

    # Connect a Morphis Client (lightweight Node) instance.
    mc = client.Client(loop, client_key=client_key, address=args.address)

    conn = yield from mc.connect()

    if not conn:
        log.warning("Connect failed, starting node instead.")
        import node

        node.loop = loop
        node.maalstroom_enabled = False

        import sys
        sys.argv = ["node.py"]

        yield from node.__main()

        yield from node.nodes[0].chord_engine.protocol_ready.wait()

        mc = node.nodes[0].chord_engine.tasks

#    if not conn:
#        log.warning("Connection failed; exiting.")
#        loop.stop()
#        return

#    dbase = init_db(args)

    yield from __process(args, loop, mc)

    # Finished request, clean up.
    if conn:
        log.info("Disconnecting.")
        yield from mc.disconnect()
    else:
        mc.engine.node.stop()

    loop.stop()

@asyncio.coroutine
def __process(args, loop, mc):
    log.info("Processing command requests...")

    if args.stat:
        r = yield from mc.send_command("stat")
        llog.printl(r.decode("UTF-8"))
        return

    if args.store_data:
        if args.i:
            data = open(args.i, "rb").read()
        else:
            data = sys.stdin.read().encode()

        def key_callback(key):
            key_enc = mbase32.encode(key)

            print("SHORT KEY: " + key_enc[:32])
            print("FULL KEY: " + key_enc)


        if args.encrypt:
            def ekc(enc_key):
                print("ENCRYPTION KEY: " + mbase32.encode(enc_key))

            store_cnt, link_cnt = yield from multipart.store_data(\
                mc.engine, data, key_callback=key_callback,\
                enc_mode=multipart.ENC_MODE_DEFAULT, enc_key_callback=ekc)
        else:
            store_cnt, link_cnt = yield from multipart.store_data(\
                mc.engine, data, key_callback=key_callback)

        return

    # Process the request (for now, we support send_get_data(..) requests.
    key, sig_bits = mutil.decode_key(args.key)

    if sig_bits:
        data_rw = yield from mc.send_find_key(key, sig_bits)
        key = data_rw.data_key
        if not key:
            log.error("Key [{}] was not found.".format(args.key))
            return

#    data_rw = yield from mc.send_get_data(key)

    #TODO: Find out why on some platforms this is needed.
    if type(key) is bytearray:
        key = bytes(key)

    r = yield from multipart.get_data_buffered(mc.engine, key)

    data = r.data

    if not data:
        log.error(\
            "Data for key [{}] was not found.".format(mbase32.encode(key)))
        return

    if args.o:
        # Write to a file instead of stdout.
        f = open(args.o, "wb")
        f.write(data)
    elif args.O:
        # Write to a file instead of stdout.
        f = open(mbase32.encode(key)[:32], "wb")
        f.write(data)
    else:
        # Write the response to stdout.
        llog.printl(data.decode())

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
