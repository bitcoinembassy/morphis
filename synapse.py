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
    #FIXME: NONCE_SIZE becomes dynamic to prevent a B.G.E.
    NONCE_SIZE = consts.MIN_NONCE_SIZE # bytes.
    MIN_DIFFICULTY = consts.MIN_DIFFICULTY # bits.

    @staticmethod
    def for_target(target_key, source_key, difficulty=MIN_DIFFICULTY):
        return Synapse(None, target_key, source_key, difficulty)

    @staticmethod
    def for_targets(target_keys, source_key, difficulty=MIN_DIFFICULTY):
        syn = Synapse(None, None, source_key, difficulty)
        syn.target_keys.extend(target_keys)
        return syn

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

        if log.isEnabledFor(logging.DEBUG):
            log.debug(\
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

        if log.isEnabledFor(logging.DEBUG):
            log.debug(\
                "synapse_pow=[{}].".format(mbase32.encode(self._synapse_pow)))

        return self._synapse_pow

    @property
    def log_distance(self):
        if self._log_distance:
            return self._log_distance

        self._log_distance =\
            mutil.calc_log_distance(self.target_key, self.synapse_pow)

        if log.isEnabledFor(logging.DEBUG):
            log.debug("log_distance=[{}].".format(self._log_distance))

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
            sshtype.encode_binary_onto(nbuf, self._pubkey)
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

        for stamp in self.stamps:
            stamp.encode_onto(nbuf)

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
            if self.signature_type != rsakey.RSASSA_PSS:
                raise Exception(\
                    "Invalid signature_type [{}].".format(self.signature_type))
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
            stamps = self.stamps
            if stamps: stamps.clear()
            while i < len(self.buf):
                i, stamp = Stamp().parse_from(self.buf[i:])
                stamps.append(stamp)

    def is_signed(self):
        return self.pubkey or self.signature_type is not None

    def check_signature(self):
        assert self.buf and self.is_signed

        if not self.key:
            self.key = rsakey.RsaKey(self.buf, i=self.pubkey_offset)

        return self.key.verify_rsassa_pss_sig(
            self.buf[:self.signature_offset], self.buf, self.signature_offset)

    def check_stamps(self):
        assert self.stamps
        #TODO: YOU_ARE_HERE
        raise Exception()

    @property
    def pubkey(self):
        if self._pubkey:
            return self._pubkey

        if self.key:
            # Try this first as buf could be filled but offsets are only filled
            # by parse and not encode.
            self._pubkey = self.key.asbytes()
        else:
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

class Stamp(object):
    def __init__(self, signed_key=None, key=None):
        self.signed_key = signed_key
        self.version = 1
        self.signature = None
        self.nonce = None
        self.key = key
        self._pubkey = None

        self.difficulty = consts.MIN_DIFFICULTY

        self._signed_data_end_idx = None
        self._pow_data_end_idx = None

        self._log_distance = None

    @property
    def stamp_pow(self):
        if self._stamp_pow:
            return self._stamp_pow

        if not self.buf:
            raise Exception("_stamp_pow is not set and self.buf is empty.")

        self._stamp_pow =\
            enc.generate_ID(self.buf[:self._pow_data_end_idx])

        if log.isEnabledFor(logging.DEBUG):
            log.debug(\
                "stamp_pow=[{}].".format(mbase32.encode(self._stamp_pow)))

        return self._stamp_pow

    @property
    def pubkey(self):
        if self._pubkey:
            return self._pubkey

        assert self.buf

        self._pubkey =\
            self.buf[self._pubkey_offset:self._pubkey_offset+self._pubkey_len]

        return self._pubkey

    @pubkey.setter
    def pubkey(self, value):
        self._pubkey = value

    @property
    def signing_key(self):
        if self._signing_key:
            return self._signing_key

        self._signing_key = enc.generate_ID(self.pubkey)

        return self._signing_key

    @property
    def log_distance(self):
        if self._log_distance:
            return self._log_distance

        self._log_distance =\
            mutil.calc_log_distance(self.signed_key, self.stamp_pow)

        if log.isEnabledFor(logging.DEBUG):
            log.debug("log_distance=[{}].".format(self._log_distance))

        return self._log_distance

    def encode(self):
        if not self.buf:
            self.buf = nbuf = bytearray()
        else:
            nbuf = self.buf
            nbuf.clear()

        self.encode_onto(nbuf)

        return nbuf

    def encode_onto(self, nbuf):
        assert len(self.signed_key) == consts.NODE_ID_BYTES
        nbuf += self.signed_key

        sshtype.encode_mpint_onto(nbuf, self.version)

        self._signed_data_end_idx = len(nbuf)

        if self.signature:
            nbuf += self.signature
        elif self.key:
            # Will be one string and one binary.
            self.key.generate_rsassa_pss_sig(nbuf, nbuf)

        self._pow_data_end_idx = len(nbuf)

        #FIXME: Make this nonce stuff use some new dynamic sizing API.
        struct.pack(">L", consts.MIN_NONCE_SIZE)
        nbuf += b' ' * consts.MIN_NONCE_SIZE
        nbuf[len(nbuf)-consts.MIN_NONCE_SIZE:] = yield from\
            asyncio.get_event_loop().run_in_executor(\
                None,\
                brute.generate_targeted_block(\
                    self.signed_key, self.difficulty, nbuf, len(nbuf),\
                    consts.MIN_NONCE_SIZE))

        self._pubkey_offset = len(nbuf) + 4
        if self._pubkey:
            nbuf += sshtype.encode_binary_onto(nbuf, self._pubkey)
        elif self.key:
            offset = len(nbuf)
            nbuf += consts.NULL_LONG
            self.key.encode_pubkey_onto(nbuf)
            struct.pack_into(">L", nbuf, offset, len(nbuf) - offset - 4)
        else:
            raise Exception()

    def parse(self):
        self.parse_from(self.buf, 0)

    def parse_from(self, buf, i):
        self.signed_key = buf[i:consts.NODE_ID_BYTES]
        i += consts.NODE_ID_BYTES

        i, self.version = sshtype.parse_mpint_from(buf, i)

        self._signed_data_end_idx = i

        self.signature_offset = i
        i, self.signature_type = sshtype.parse_string_from(self.buf, i)
        # For now we only support rsassa_pss.
        if self.signature_type != rsakey.RSASSA_PSS:
            raise Exception(\
                "Invalid signature_type [{}].".format(self.signature_type))
        sig_bin_len = struct.unpack_from(">L", self.buf, i)[0]
        i += 4 + sig_bin_len

        self._pow_data_end_idx = i

        i, self.nonce = sshtype.parse_binary_from(buf, i)

        self.pubkey_len = struct.unpack_from(">L", self.buf, i)[0]
        i += 4
        self._pubkey_offset = i
        i += self._pubkey_len

        return i, self

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
