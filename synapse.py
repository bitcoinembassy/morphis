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
import rsakey
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
        self._pubkey = None
        self.signature = None
        self.nonce = None
        self.stamps = []
        ##.

        self.difficulty = difficulty

        self.signature_offset = None
        self.pubkey_offset = None
        self.nonce_offset = None

        self.signature_type = None
        self.pubkey_len = None

        self._synapse_key = None
        self._synapse_pow = None
        self._signing_key = None
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

        # 0 and >=128 are reserved; also, logic requires at least one
        # target_key anyways.
        assert len(self.target_keys) > 0 and len(self.target_keys) < 128
        nbuf += struct.pack("B", len(self.target_keys) & 0xff)
        for tkey in self.target_keys:
            assert len(tkey) == consts.NODE_ID_BYTES
            nbuf += tkey

        assert len(self.source_key) == consts.NODE_ID_BYTES
        nbuf += self.source_key

        if not self.timestamp:
            self.timestamp = mutil.utc_timestamp()
        sshtype.encode_mpint_onto(nbuf, int(self.timestamp*1000))

        self.signature_offset = len(nbuf)
        if self.signature:
            nbuf += self.signature
        elif self.key:
            # Will be one string and one binary.
            self.key.generate_rsassa_pss_sig(nbuf, nbuf)
        else:
            assert not self._pubkey
            sshtype.encode_string_onto(nbuf, "")

        if self._pubkey:
            offset = len(nbuf)
            nbuf += consts.NULL_LONG
            nbuf += self._pubkey
            struct.pack_into(">L", nbuf, offset, len(nbuf) - offset - 4)
        elif self.key:
            offset = len(nbuf)
            nbuf += consts.NULL_LONG
            self.key.encode_pubkey_onto(nbuf)
            struct.pack_into(">L", nbuf, offset, len(nbuf) - offset - 4)
        else:
            assert not self.signature
            sshtype.encode_string_onto(nbuf, "")

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
        if ntarget_keys >= 128:
            raise Exception(\
                "ntarget_keys=[{}] is reserved.".format(ntarget_keys))

        for idx in range(ntarget_keys):
            end = i + consts.NODE_ID_BYTES
            self.target_keys.append(self.buf[i:end])
            i = end

        end = i + consts.NODE_ID_BYTES
        self.source_key = self.buf[i:end]
        i = end

        i, tsms = sshtype.parse_mpint_from(self.buf, i)
        self.timestamp = tsms/1000

        self.signature_offset = i
        i, self.signature_type = sshtype.parse_string_from(self.buf, i)
        if self.signature_type:
            # For now we only support rsassa_pss.
            assert\
                self.signature_type == rsakey.RSASSA_PSS, self.signature_type
            sig_bin_len = struct.unpack_from(">L", self.buf, i)[0]
            i += 4 + sig_bin_len
        else:
            self.signature_type = None

        self.pubkey_len = struct.unpack_from(">L", self.buf, i)[0]
        i += 4
        if self.pubkey_len:
            assert self.signature_type
            self.pubkey_offset = i
            i += self.pubkey_len

        self.nonce_offset = i
        end = i + Synapse.NONCE_SIZE
        self.nonce = self.buf[i:end]
        i = end

        if i < len(self.buf):
            self.stamps = self.buf[i:]

    def is_signed(self):
        return self.signature_type is not None

    def check_signature(self):
        assert self.buf and self.is_signed

        if not self.key:
            self.key = rsakey.RsaKey(self.buf, i=self.pubkey_offset)

        return self.key.verify_rsassa_pss_sig(
            self.buf[:self.signature_offset], self.buf, self.signature_offset)

    @property
    def pubkey(self):
        if self._pubkey:
            return self._pubkey

        self._pubkey =\
            self.buf[self.pubkey_offset:self.pubkey_offset+self.pubkey_len]

        return self._pubkey

    @pubkey.setter
    def pubkey(self, value):
        self._pubkey = value

    @property
    def signing_key(self):
        assert self.is_signed()

        if self._signing_key:
            return self._signing_key

        self._signing_key = enc.generate_ID(self.pubkey)

        return self._signing_key

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

        self.start_timestamp = 0
        self.end_timestamp = 0
        self.start_key = b''
        self.end_key = b''
        self.minimum_pow = 0
        self.query = None

        if buf:
            self.parse_from(buf, 0)

    def encode(self):
        if not self.buf:
            self.buf = nbuf = bytearray()
        else:
            nbuf = self.buf
            nbuf.clear()

        self.encode_onto(nbuf)

        return nbuf

    def encode_onto(self, nbuf):
        sshtype.encode_mpint_onto(nbuf, int(self.start_timestamp*1000))
        sshtype.encode_mpint_onto(nbuf, int(self.end_timestamp*1000))
        sshtype.encode_binary_onto(nbuf, self.start_key)
        sshtype.encode_binary_onto(nbuf, self.end_key)
        nbuf += struct.pack(">H", self.minimum_pow)
        self.query.encode_onto(nbuf)

    def parse(self):
        self.parse_from(self.buf, 0)

    def parse_from(self, buf, i):
        i, tsms = sshtype.parse_mpint_from(buf, i)
        self.start_timestamp = tsms/1000
        i, tsms = sshtype.parse_mpint_from(buf, i)
        self.end_timestamp = tsms/1000

        i, self.start_key = sshtype.parse_binary_from(buf, i)
        i, self.end_key = sshtype.parse_binary_from(buf, i)

        self.minimum_pow = struct.unpack_from(">H", buf, i)[0]
        i += 2

        i, self.query = SynapseRequest.Query().parse_from(buf, i)

        return i, self

    class Query(object):
        class Type(Enum):
            key = 1
            and_ = 2
            or_ = 3

        def __init__(self, type_=None, entries=None):
            if type(entries) is SynapseRequest.Query.Key:
                self.type = SynapseRequest.Query.Type.key
            else:
                assert not entries or entries in type(list, tuple)
                self.type = type_

            if not entries:
                entries = []
            self.entries = entries

        def encode_onto(self, buf):
            buf += struct.pack("B", self.type.value)
            if self.type is SynapseRequest.Query.Type.key:
                self.entries.encode_onto(buf)
            else:
                buf += struct.pack(">H", len(self.entries))
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
                cnt = struct.unpack_from(">H", buf, i)[0]
                i += 2
                for n in range(cnt):
                    i, entry = SynapseRequest.Query().parse_from(buf, i)
                    self.entries.append(entry)

            return i, self

        class Key(object):
            class Type(Enum):
                target = 1
                source = 2
                signing = 3

            def __init__(self, type_=None, value=None):
                self.type = type_
                self.value = value

            def encode_onto(self, buf):
                buf += struct.pack("B", self.type.value)
                sshtype.encode_binary_onto(buf, self.value)

            def parse_from(self, buf, i):
                ev = struct.unpack_from("B", buf, i)[0]
                i += 1
                self.type = SynapseRequest.Query.Key.Type(ev)
                i, self.value = sshtype.parse_binary_from(buf, i)

                return i, self
