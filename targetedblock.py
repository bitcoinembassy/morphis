# Copyright (c) 2016  Sam Maloney.
# License: GPL v2.

import llog

import logging

import consts
import enc
from morphisblock import MorphisBlock

log = logging.getLogger(__name__)

class TargetedBlock(MorphisBlock):
    NOONCE_OFFSET = MorphisBlock.HEADER_BYTES
    NOONCE_SIZE = 64 #FIXME: This was suppose to be 64 bits, not bytes.
    BLOCK_OFFSET = MorphisBlock.HEADER_BYTES + NOONCE_SIZE\
        + 2 * consts.NODE_ID_BYTES

    @staticmethod
    def set_nonce(data, nonce_bytes):
        assert type(nonce_bytes) in (bytes, bytearray)
        lenn = len(nonce_bytes)
        end = TargetedBlock.NOONCE_OFFSET + TargetedBlock.NOONCE_SIZE
        start = end - lenn
        data[start:end] = nonce_bytes

    def __init__(self, buf=None):
        self.nonce = b' ' * TargetedBlock.NOONCE_SIZE
        self.target_key = None
        self.block_hash = None
        self.block = None

        super().__init__(consts.BlockType.targeted.value, buf)

    def encode(self):
        nbuf = super().encode()

        assert len(self.nonce) == TargetedBlock.NOONCE_SIZE
        nbuf += self.nonce
        assert self.target_key is not None\
            and len(self.target_key) == consts.NODE_ID_BYTES
        nbuf += self.target_key

        nbuf += b' ' * consts.NODE_ID_BYTES # block_hash placeholder.

        assert len(nbuf) == TargetedBlock.BLOCK_OFFSET

        if type(self.block) in (bytes, bytearray):
            nbuf += self.block
        else:
            self.block.encode(nbuf)

        self.block_hash = enc.generate_ID(nbuf[TargetedBlock.BLOCK_OFFSET:])
        block_hash_offset = TargetedBlock.BLOCK_OFFSET-consts.NODE_ID_BYTES
        nbuf[block_hash_offset:TargetedBlock.BLOCK_OFFSET] = self.block_hash

        return nbuf

    def parse(self):
        i = super().parse()

        self.nonce = self.buf[i:i+TargetedBlock.NOONCE_SIZE]
        i += TargetedBlock.NOONCE_SIZE
        self.target_key = self.buf[i:i+consts.NODE_ID_BYTES]
        i += consts.NODE_ID_BYTES
        self.block_hash = self.buf[i:i+consts.NODE_ID_BYTES]
        i += consts.NODE_ID_BYTES

class Synapse():
    def __init__(self, buf=None):
        assert len(target_key) == consts.NODE_ID_BYTES
        assert len(dest_key) == consts.NODE_ID_BYTES
        assert not ext_key or len(ext_key) == consts.NODE_ID_BYTES
        self.target_key = None
        self.dest_key = None
        self.ext_key = None
        self.timestamp = None
        self.signature = None
        self.nonce = None

    def encode(self):
        nbuf = bytearray()

        nbuf += self.target_key
        nbuf += self.dest_key
        nbuf += self.ext_key if self.ext_key else consts.NULL_KEY

        if not self.timestamp:
            self.timestamp = int(time.time() * 1000)

        nbuf += sshtype.encodeMpint(self.timestamp)

        #TODO: YOU_ARE_HERE: signature?
