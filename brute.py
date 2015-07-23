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

def generate_targeted_block(prefix, nbits, data, noonce_offset, noonce_size):
    "Brute force finds a noonce for the passed data which allows the data to"
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
                _find_noonce,\
                args=(rp,))

            pipes.append(lp)
            refs.append(rp)

            lp.send((i, prefix, nbits, data, noonce_offset, noonce_size))

        ready = mp.connection.wait(pipes)
        block = ready[0].recv()
    except:
        log.exception("")

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
    except:
        log.exception("")

    pool.terminate()

    return key

def _find_noonce(rp):
    try:
        __find_noonce(rp)
    except:
        log.exception("__find_noonce(..)")

def __find_noonce(rp):
    log.debug("Worker running.")

    wid, prefix, nbits, data, noonce_offset, noonce_size = rp.recv()

    max_dist = HASH_BITS - nbits
    nbytes = int(nbits / 8)
    nbytes += 4 # Extra bytes to increase probability of enough possibilities.
    nbytes = min(nbytes, noonce_size)
    ne = noonce_offset + noonce_size
    noonce_offset = ne - nbytes

    noonce = wid

    while True:
        noonce_bytes = noonce.to_bytes(nbytes, "big")
        data[noonce_offset:ne] = noonce_bytes

        h = enc.generate_ID(data)

        try:
            dist, direction = mutil.calc_log_distance(h, prefix)
            match = dist <= max_dist and direction == -1
        except IndexError:
            log.debug("Exactly matched prefix.")
            match = True

        if match:
            if log.isEnabledFor(logging.INFO):
                log.info("noonce_bytes=[{}]."\
                    .format(mutil.hex_string(noonce_bytes)))
            if log.isEnabledFor(logging.DEBUG):
                log.debug("resulting block=[\n{}]."\
                    .format(mutil.hex_dump(data)))

            rp.send(noonce_bytes)
            return

        noonce += WORKERS

def _find_key(rp):
    try:
        __find_key(rp)
    except:
        log.exception("__find_key(..)")

def __find_key(rp):
    log.debug("Worker running.")

    wid, prefix = rp.recv()

    while True:
        key = rsakey.RsaKey.generate(bits=4096)
        pubkey_bytes = key.asbytes()

        pubkey_hash = enc.generate_ID(pubkey_bytes)

        pubkey_hash_enc = mbase32.encode(pubkey_hash)

        if pubkey_hash_enc.startswith(prefix):
            if log.isEnabledFor(logging.INFO):
                log.info("Worker #{} found key.".format(wid))

            rp.send(key._encode_key())
            return

def main():
    log.info("Testing...")

    r = generate_targeted_block(\
        mbase32.decode("yyyyyyyy"), 20, b"test data message", 0, 4)

    log.info("Done, r=[{}].".format(r))

if __name__ == "__main__":
    main()

