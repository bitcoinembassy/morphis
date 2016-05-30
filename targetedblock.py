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
    NOONCE_SIZE = 8 #FIXME: This was suppose to be 64 bits, not bytes.

    def __init__(self, buf=None):
        self.buf = buf
        if buf:
            self.parse()
            return

        #ntargets = len(self.target_keys).
        self.target_keys = []
        self.source_key = None
        self.timestamp = None
        #signature
        self.nonce = None
        self.stamps = None

    @property
    def target_key(self):
        return self.target_keys[0]

    @setter.target_key
    def target_key(self, value):
        nkeys = len(self.target_keys)
        if nkeys == 0:
            self.target_keys.append(value)
        else:
            self.target_keys[0] = value

    @asyncio.coroutine
    def encode(self, key, difficulty):
        self.buf = nbuf = bytearray()

        # 0 is reserved; also, spec requires at least one target_key anyways.
        assert len(self.target_keys) > 0 and len(self.target_keys) < 256
        nbuf += struct.pack("B", len(self.target_keys) & 0xff)
        for tkey in self.target_keys:
            assert len(tkey) == consts.NODE_ID_BYTES
            nbuf += tkey

        assert len(self.source_key) == consts.NODE_ID_BYTES
        nbuf += self.source_key

        if not self.timestamp:
            self.timestamp = int(time.time() * 1000)
        nbuf += sshtype.encodeMpint(self.timestamp)

        nbuf += key.asbytes()
        nbuf += key.calc_rsassa_pss_sig(nbuf)

        nonce_offset = len(nbuf)
        nbuf += b' ' * TargetedBlock.NOONCE_SIZE
        nonce_bytes =\
            yield from self._calculate_nonce(nbuf, nonce_offset, difficulty)
        self.set_nonce(nbuf, nonce_bytes, nonce_offset)

        #TODO: YOU_ARE_HERE: Keyspace/stamps.

    def set_nonce(data, nonce_bytes, offset):
        assert type(nonce_bytes) in (bytes, bytearray)
        lenn = len(nonce_bytes)
        end = offset + NOONCE_SIZE
        start = end - lenn
        data[start:end] = nonce_bytes

    @asyncio.coroutine
    def _calculate_nonce(self, buf, offset, difficulty):
        if log.isEnabledFor(logging.INFO):
            log.info(\
                "Attempting work on Synapse"\
                    " (target=[{}], difficulty=[{}])."\
                        .format(mbase32.encode(self.target_key), difficulty))

        def threadcall():
            return brute.generate_targeted_block(\
                self.target_key, difficulty, buf,\
                offset,\
                NOONCE_SIZE)

        nonce_bytes = yield from self.loop.run_in_executor(None, threadcall)

        if log.isEnabledFor(logging.INFO):
            log.info(\
                "Work found nonce [{}].".format(mbase32.encode(nonce_bytes)))

        return nonce_bytes
