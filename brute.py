import llog

import logging
import multiprocessing as mp
import os
import time

import enc
import mbase32
import multipart
import mutil

log = logging.getLogger(__name__)

WORKERS = os.cpu_count()
HASH_BITS = enc.ID_BITS
HASH_BYTES = HASH_BITS >> 3

def generate_targeted_block(prefix, nbits, data, noonce_offset, noonce_size):
    if type(data) is bytes:
        data = bytearray(data)
    else:
        assert type(data) is bytearray

    block = None

    pool = mp.Pool(WORKERS)

    def done(result):
        nonlocal block
        log.debug("done(..) called.")
        pool.terminate()

        block = result

    pipes = []
    refs = []

    try:
        for i in range(WORKERS):
            log.debug("Starting worker.")

            lp, rp = mp.Pipe()

            pool.apply_async(\
                find_noonce,\
                args=(rp,),\
                callback=done)

            pipes.append(lp)
            refs.append(data)
            refs.append(rp)

            lp.send((prefix, nbits, data, noonce_offset, noonce_size))

        pool.close()
        pool.join()

    except:
        log.exception()
        pool.terminate()

    return block

def find_noonce(rp):
    try:
        _find_noonce(rp)
    except:
        log.exception("_find_noonce(..)")

def _find_noonce(rp):
    log.debug("Worker running.")

    prefix, nbits, data, noonce_offset, noonce_size = rp.recv()

    max_dist = HASH_BITS - nbits
    nbytes = int(nbits / 8)
    nbytes += 4 # Extra bytes to increase probability of enough possibilities.
    nbytes = min(nbytes, noonce_size)
    ne = noonce_offset + noonce_size
    noonce_offset = ne - nbytes

    noonce = 0

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
            log.info("noonce_bytes=[{}].".format(noonce_bytes))
            return noonce_bytes

        noonce += WORKERS

def main():
    log.info("Testing...")

    r = generate_targeted_block(\
        mbase32.decode("yyyyyyyy"), 20, b"test data message", 0, 4)

    log.info("Done, r=[{}].".format(r))

if __name__ == "__main__":
    main()

