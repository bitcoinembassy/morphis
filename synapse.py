# Höfundarréttur (c) eilífur  Heimur-Heilinn
# License: GPL v2.

import llog

import asyncio
from enum import Enum
import logging
import struct

import brute
import consts
import enc
import mbase32
import mutil
import sshtype

log = logging.getLogger(__name__)

# Data Object.
class Synapse(object):
    NONCE_SIZE = 8
    MIN_DIFFICULTY = 8 # bits.

    @staticmethod
    def for_target(target_key, source_key, difficulty=MIN_DIFFICULTY):
        return Synapse(None, target_key, source_key, difficulty)

    def __init__(self, buf=None, target_key=None, source_key=None,\
            difficulty=MIN_DIFFICULTY):
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

        self.difficulty = difficulty

        self.nonce_offset = None

        self._synapse_key = None
        self._synapse_pow = None
        self._log_distance = None

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
    def log_distance(self):
        if self._log_distance:
            return self._log_distance

        self._log_distance =\
            mutil.calc_log_distance(self.target_key, self.synapse_pow)

        if log.isEnabledFor(logging.INFO):
            log.info("log_distance=[{}].".format(self._log_distance))

        return self._log_distance

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
            self.timestamp = mutil.utc_timestamp()
        nbuf += sshtype.encodeMpint(int(self.timestamp*1000))

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

        i, tsms = sshtype.parse_mpint_from(self.buf, i)
        self.timestamp = tsms/1000

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

# DHT API Objects.
class SynapseRequest(object):
    def __init__(self, buf=None):
        self.buf = buf

        self.start_timestamp = None
        self.end_timestamp = None
        self.start_key = None
        self.end_key = None
        self.minimum_pow = None
        self.query = None

        if buf:
            self.parse_from(buf, 0)

    def encode(self):
        if not self.buf:
            self.buf = nbuf = bytearray()
        else:
            nbuf = self.buf
            nbuf.clear()

        nbuf += sshtype.encodeMpint(int(self.start_timestamp*1000))
        nbuf += sshtype.encodeMpint(int(self.end_timestamp*1000))
        nbuf += sshtype.encodeBinary(self.start_key)
        nbuf += sshtype.encodeBinary(self.end_key)
        nbuf += struct.pack(">H", self.minimum_pow)
        self.query.encode_onto(nbuf)

        return nbuf

    def parse(self):
        self.parse_from(self.buf, 0)

    def parse_from(self, buf, i):
        i, tsms = sshtype.parse_mpint_from(buf, 0)
        self.start_timestamp = tsms/1000
        i, tsms = sshtype.parse_mpint_from(buf, i)
        self.end_timestamp = tsms/1000

        i, self.start_key = sshtype.parse_binary_from(buf, i)
        i, self.end_key = sshtype.parse_binary_from(buf, i)

        self.minimum_pow = struct.unpack_from(">S", buf, i)[0]
        i += 2

        i, self.query = SynapseRequest.Query().parse_from(buf, i)

        return i, self

    class Query(object):
        class Type(Enum):
            key = 1
            and_ = 2
            or_ = 3

        def __init__(self, entries=None, type_=None):
            if type(entries) in (bytes, bytearray):
                self.type = SynapseRequest.Query.Type.key
                self.entries = SynapseRequest.Query.Key(entries)
            else:
                assert not entries or entries in type(list, tuple)
                self.type = type_
                if not entries:
                    entries = []
                self.entries = entries

        def encode_onto(self, buf):
            buf += struct.pack("B", self.type)
            if self.type is SynapseRequest.Query.Type.key:
                self.entries.encode_onto(buf)
            else:
                buf += struct.pack(">S", len(self.entries))
                for entry in self.entries:
                    entry.encode_onto(buf)

        def parse_from(self, buf, i):
            ev = struct.unpack_from("B", buf, i)[0]
            i += 1
            self.type = SynapseRequest.Query.Type(ev)

            if self.type is SynapseRequest.Query.Type.key:
                i, self.entries = SynapseRequest.Query.Key().parse_from(buf, i)
            else:
                self.entries = []
                cnt = struct.unpack_from(">S", buf, i)[0]
                i += 2
                for n in range(cnt):
                    i, entry = SynapseRequest.Query().parse_from(buf, i)
                    self.entries.append(entry)

            return i, self

        class Key(object):
            class Type(Enum):
                target = 1
                source = 2

            def __init__(self, type_, value):
                self.type = type_
                self.value = value

            def encode_onto(self, buf):
                buf += struct.pack("B", self.type.value)
                buf += sshtype.encodeBinary(self.value)

            def parse_from(self, buf, i):
                ev = struct.unpack_from("B", buf, i)[0]
                i += 1
                self.type = SynapseRequest.Query.Key.Type(ev)
                i, self.value = sshtype.parse_binary_from(buf, i)

                return i, self
