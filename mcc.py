import llog

import argparse
import asyncio
import logging
import os
import time

import base58
import client
import dmail
import rsakey

log = logging.getLogger(__name__)

def main():
    global loop

    loop = asyncio.get_event_loop()

    asyncio.async(_main(), loop=loop)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        log.info("Got KeyboardInterrupt; shutting down.")
    except:
        log.exception("loop.run_forever() threw:")

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
        "--stat",\
        help="Report node status.",\
        action="store_true")
    parser.add_argument("-l", dest="logconf",\
        help="Specify alternate logging.ini [IF SPECIFIED, THIS MUST BE THE"\
            " FIRST PARAMETER!].")

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

    log.info("Processing command requests...")

    if args.stat:
        r = yield from mc.send_command("stat")
        print(r.decode("UTF-8"), end='')

    if args.create_dmail:
        print("SENDING")
        key = rsakey.RsaKey.generate(bits=4096)
        ekey = base58.encode(key._encode_key())

        dms = dmail.DmailSite()
        dms.generate()
        edms = base58.encode(dms.export())

        r = yield from mc.send_command(\
            "storeukeyenc {} {} {} True"\
                .format(ekey, edms, int(time.time()*1000)))

        if r:
            print("privkey: {}".format(ekey))
            p1 = r.find(b']')
            r = r[10:p1].decode("UTF-8")
            print("dmail address: {}".format(r))

    log.info("Disconnecting.")

    yield from mc.disconnect()

    loop.stop()

if __name__ == "__main__":
    main()
