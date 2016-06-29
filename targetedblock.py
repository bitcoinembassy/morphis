# Copyright (c) 2016  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
import logging
import struct

import brute
import consts
import enc
import mbase32
from morphisblock import MorphisBlock
import mutil
import sshtype

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

class Synapse(object):
    NONCE_SIZE = 8
    MIN_DIFFICULTY = 8 # bits.

    @staticmethod
    def for_target(target_key, source_key):
        return Synapse(None, target_key, source_key)

    def __init__(self, buf=None, target_key=None, source_key=None):
        self.buf = buf

        ## Encoded fields.
        #ntargets = len(self.target_keys).
        self.target_keys = []
        if target_key:
            self.target_keys.append(target_key)
        self.source_key = source_key
        self.timestamp = None
        self.key = None
        self.pubkey = None
        self.signature = None
        self.nonce = None
        self.stamps = []
        ##.

        self.difficulty = Synapse.MIN_DIFFICULTY

        self.nonce_offset = None

        self._synapse_key = None
        self._synapse_pow = None

        if buf:
            self.parse()

    @property
    def synapse_key(self):
        if self._synapse_key:
            return self._synapse_key

        if not self.buf:
            raise Exception("_synapse_key is not set and self.buf is empty.")

        self._synapse_key =\
            enc.generate_ID(self.buf[:self.nonce_offset])

        if log.isEnabledFor(logging.INFO):
            log.info(\
                "synapse_key=[{}].".format(mbase32.encode(self._synapse_key)))

        return self._synapse_key

    @property
    def synapse_pow(self):
        if self._synapse_pow:
            return self._synapse_pow

        if not self.buf:
            raise Exception("_synapse_pow is not set and self.buf is empty.")

        self._synapse_pow =\
            enc.generate_ID(self.buf[:self.nonce_offset + Synapse.NONCE_SIZE])

        if log.isEnabledFor(logging.INFO):
            log.info(\
                "synapse_pow=[{}].".format(mbase32.encode(self._synapse_pow)))

        return self._synapse_pow

    @property
    def target_key(self):
        return self.target_keys[0]

    @target_key.setter
    def target_key(self, value):
        nkeys = len(self.target_keys)
        if nkeys == 0:
            self.target_keys.append(value)
        else:
            self.target_keys[0] = value

    @asyncio.coroutine
    def encode(self):
        "Encode the packet fields into the self.buf bytearray and return it."
        if not self.buf:
            self.buf = nbuf = bytearray()
        else:
            nbuf = self.buf
            nbuf.clear()

        # 0 is reserved; also, spec requires at least one target_key anyways.
        assert len(self.target_keys) > 0 and len(self.target_keys) < 256
        nbuf += struct.pack("B", len(self.target_keys) & 0xff)
        for tkey in self.target_keys:
            assert len(tkey) == consts.NODE_ID_BYTES
            nbuf += tkey

        assert len(self.source_key) == consts.NODE_ID_BYTES
        nbuf += self.source_key

        if not self.timestamp:
            self.timestamp = int(mutil.utc_timestamp() * 1000)
        nbuf += sshtype.encodeMpint(self.timestamp)

        if self.signature:
            nbuf += sshtype.encodeBinary(self.signature)
        elif self.key:
            nbuf += sshtype.encodeBinary(self.key.calc_rsassa_pss_sig(nbuf))
        else:
            nbuf += sshtype.encodeBinary(b'')

        if self.pubkey:
            nbuf += sshtype.encodeBinary(self.pubkey)
        elif self.key:
            nbuf += sshtype.encodeBinary(self.key.asbytes())
        else:
            nbuf += sshtype.encodeBinary(b'')

        self.nonce_offset = nonce_offset = len(nbuf)
        nbuf += b' ' * Synapse.NONCE_SIZE

        nonce_bytes = yield from\
            self._calculate_nonce(nbuf, nonce_offset, self.difficulty)

        self._store_nonce(nbuf, nonce_bytes, nonce_offset)

        if self.stamps:
            nbuf += self.stamps

        return nbuf

    def parse(self):
        ntarget_keys = struct.unpack_from("B", self.buf, 0)[0]
        i = 1

        if not ntarget_keys:
            raise Exception("ntarget_keys=0 is reserved.")

        for idx in range(ntarget_keys):
            end = i + consts.NODE_ID_BYTES
            self.target_keys.append(self.buf[i:end])
            i = end

        end = i + consts.NODE_ID_BYTES
        self.source_key = self.buf[i:end]
        i = end

        i, self.timestamp = sshtype.parse_mpint_from(self.buf, i)

        # For now we only support rsassa_pss.
        i, self.signature = sshtype.parse_binary_from(self.buf, i)
        i, self.key_bytes = sshtype.parse_binary_from(self.buf, i)

        self.nonce_offset = i
        end = i + Synapse.NONCE_SIZE
        self.nonce = self.buf[i:end]
        i = end

        if i < len(self.buf):
            self.stamps = self.buf[i:]

    @asyncio.coroutine
    def _calculate_nonce(self, buf, offset, difficulty):
        if log.isEnabledFor(logging.INFO):
            log.info(\
                "Attempting work on Synapse"\
                    " (target=[{}], difficulty=[{}])."\
                        .format(mbase32.encode(self.target_key), difficulty))

        def threadcall():
            return brute.generate_targeted_block(\
                self.target_key, difficulty, buf, offset, Synapse.NONCE_SIZE)

        nonce_bytes = yield from\
            asyncio.get_event_loop().run_in_executor(None, threadcall)

        if log.isEnabledFor(logging.INFO):
            log.info(\
                "Work found nonce [{}].".format(mutil.hex_string(nonce_bytes)))

        return nonce_bytes

    def _store_nonce(self, data, nonce_bytes, offset):
        assert type(nonce_bytes) in (bytes, bytearray)
        lenn = len(nonce_bytes)
        end = offset + Synapse.NONCE_SIZE
        start = end - lenn
        self.nonce = data[start:end] = nonce_bytes
