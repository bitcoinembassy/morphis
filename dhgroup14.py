# Copyright (c) 2014-2015  Sam Maloney.
# License: LGPL

import llog

import os
import logging
from hashlib import sha1

b0000000000000000 = bytes((0x00,)) * 8
b7fffffffffffffff = bytes((0x7f,)) + bytes((0xff,)) * 7

class DhGroup14(object):
    # http://tools.ietf.org/html/rfc3526#section-3
    P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    G = 2

    def __init__(self):
        self.x = None
        self.e = None
        self.f = None
        self.k = None

    def generate_x(self):
        "generate an 'x' (1 < x < q), where q is (p-1)/2."
        "p is a 256-byte (2048-bit) number, where the first ?? bits are 1. "
        "therefore ?? q can be approximated as a 2^2047.  we drop the subset"
        "of potential x where the first 63 bits are 1, because some of those"
        "will be larger than q (but this is a tiny tiny subset of potential"
        "x)."

        while True:
            xb = bytearray(os.urandom(256))
            xb[0] = xb[0] & 0x7f

            start = xb[:8]
            if start != b7fffffffffffffff and start != b0000000000000000:
                break

        self.x = int.from_bytes(xb, "big")

    def generate_e(self):
        self.e = pow(self.G, self.x, self.P)

    def calculate_k(self):
        k = self.k
        if not k:
            k = self.k = pow(self.f, self.x, self.P)
        return k
