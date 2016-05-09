# Copyright (c) 2016  Sam Maloney.
# License: GPL v2.

import llog

import logging
import struct

import consts

log = logging.getLogger(__name__)

class MorphisBlock(object):
    UUID = b'\x86\xa0\x47\x79\xc1\x2e\x4f\x48\x90\xc3\xee\x27\x53\x6d\x26\x96'
    HEADER_BYTES = 31

    @staticmethod
    def parse_block_type(buf):
        return struct.unpack_from(">L", buf, 16 + 7)[0]

    def __init__(self, block_type=None, buf=None):
        self.buf = buf
        self.block_type = block_type
        self.ext_type = 0

        if not buf:
            return

        self.parse()

    def encode(self):
        nbuf = bytearray()

        nbuf += MorphisBlock.UUID
        nbuf += b"MORPHiS"
        nbuf += struct.pack(">L", self.block_type)
        nbuf += struct.pack(">L", self.ext_type)

        self.buf = nbuf

        return nbuf

    def parse(self):
        assert self.buf[:16] == MorphisBlock.UUID
        i = 16

        i += 7 # MORPHiS

        block_type = struct.unpack_from(">L", self.buf, i)[0]
        if self.block_type:
            if block_type != self.block_type:
                raise Exception("Expecting block_type [{}] but got [{}]."\
                    .format(self.block_type, block_type))
        self.block_type = block_type
        i += 4

        self.ext_type = struct.unpack_from(">L", self.buf, i)[0]
        i += 4

        return i
