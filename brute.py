# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import logging
import multiprocessing as mp
import os
import time

import enc
import mbase32
import multipart
import mutil
import rsakey

log = logging.getLogger(__name__)

WORKERS = os.cpu_count()
HASH_BITS = enc.ID_BITS
HASH_BYTES = HASH_BITS >> 3

def generate_targeted_block(prefix, nbits, data, nonce_offset, nonce_size):
    "Brute force finds a nonce for the passed data which allows the data to"
    " hash to the desired prefix with nbits matching. This is the first hash"
    " of the block being targetd, thus the key, the id is not what is bruted."

    if type(data) is bytes:
        data = bytearray(data)
    else:
        assert type(data) is bytearray

    block = None

    pool = mp.Pool(WORKERS)

    pipes = []
    refs = []

    try:
        for i in range(WORKERS):
            log.debug("Starting worker.")

            lp, rp = mp.Pipe()

            pool.apply_async(\
                _find_nonce,\
                args=(rp,))

            pipes.append(lp)
            refs.append(rp)

            lp.send((i, prefix, nbits, data, nonce_offset, nonce_size))

        ready = mp.connection.wait(pipes)
        block = ready[0].recv()
    except Exception:
        log.exception("Exception generating targeted block.")

    log.info("Found TargetedBlock nonce; terminating workers.")

    pool.terminate()

    return block

def generate_key(prefix):
    assert type(prefix) is str

    key = None

    pool = mp.Pool(WORKERS)

    pipes = []
    refs = []

    try:
        for i in range(WORKERS):
            log.debug("Starting worker.")

            lp, rp = mp.Pipe()

            pool.apply_async(\
                _find_key,\
                args=(rp,))

            pipes.append(lp)
            refs.append(rp)

            lp.send((i, prefix))

        ready = mp.connection.wait(pipes)
        privdata = ready[0].recv()
        key = rsakey.RsaKey(privdata=privdata)
    except Exception:
        log.exception("Exception generating key.")

    pool.terminate()

    return key

def _find_nonce(rp):
    try:
        __find_nonce(rp)
    except Exception:
        log.exception("__find_nonce(..)")

def __find_nonce(rp):
#    log.debug("Worker running.")

    wid, prefix, nbits, data, nonce_offset, nonce_size = rp.recv()

    max_dist = HASH_BITS - nbits
    nbytes = int(nbits / 8)
    nbytes += 4 # Extra bytes to increase probability of enough possibilities.
    nbytes = min(nbytes, nonce_size)
    ne = nonce_offset + nonce_size
    nonce_offset = ne - nbytes

    nonce = wid

    while True:
        nonce_bytes = nonce.to_bytes(nbytes, "big")
        data[nonce_offset:ne] = nonce_bytes

        h = enc.generate_ID(data)

        try:
            dist, direction = mutil.calc_log_distance(h, prefix)
            match = dist <= max_dist and direction == -1
        except IndexError:
#            log.debug("Exactly matched prefix.")
            match = True

        if match:
#            if log.isEnabledFor(logging.INFO):
#                log.info("nonce_bytes=[{}]."\
#                    .format(mutil.hex_string(nonce_bytes)))
#            if log.isEnabledFor(logging.DEBUG):
#                log.debug("resulting block=[\n{}]."\
#                    .format(mutil.hex_dump(data)))

            rp.send(nonce_bytes)
            return

        nonce += WORKERS

def _find_key(rp):
    try:
        __find_key(rp)
    except Exception:
        log.exception("__find_key(..)")

def __find_key(rp):
#    log.debug("Worker running.")

    wid, prefix = rp.recv()

    while True:
        key = rsakey.RsaKey.generate(bits=4096)
        pubkey_bytes = key.asbytes()

        pubkey_hash = enc.generate_ID(pubkey_bytes)

        pubkey_hash_enc = mbase32.encode(pubkey_hash)

        if pubkey_hash_enc.startswith(prefix):
#            if log.isEnabledFor(logging.INFO):
#                log.info("Worker #{} found key.".format(wid))

            rp.send(key._encode_key())
            return

def main():
    log.info("Testing...")

    r = generate_targeted_block(\
        mbase32.decode("yyyyyyyy"), 20, b"test data message", 0, 4)

    log.info("Done, r=[{}].".format(r))

if __name__ == "__main__":
    main()

