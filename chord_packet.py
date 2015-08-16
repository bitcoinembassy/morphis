# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

from enum import Enum
import logging
import struct

from chordexception import ChordException
from db import Peer
import peer as mnpeer
import sshtype

# Chord Message Types.
CHORD_MSG_RELAY = 100
CHORD_MSG_NODE_INFO = 110
CHORD_MSG_GET_PEERS = 115
CHORD_MSG_PEER_LIST = 120
CHORD_MSG_FIND_NODE = 150
CHORD_MSG_GET_DATA = 160
CHORD_MSG_DATA_RESPONSE = 162
CHORD_MSG_DATA_PRESENCE = 165
CHORD_MSG_STORE_DATA = 170
CHORD_MSG_STORE_KEY = 171
CHORD_MSG_DATA_STORED = 172
CHORD_MSG_STORAGE_INTEREST = 175

class DataMode(Enum):
    none = 0
    get = 10
    store = 20

log = logging.getLogger(__name__)

class ChordMessage(object):
    @staticmethod
    def parse_type(buf):
        return struct.unpack("B", buf[0:1])[0]

    def __init__(self, packet_type=None, buf=None):
        self.buf = buf
        self.packet_type = packet_type

        if not buf:
            return

        self._packet_type = packet_type # Expected packet_type.

        self.parse()

    def parse(self):
        self.packet_type = struct.unpack("B", self.buf[0:1])[0]

        if self._packet_type and self.packet_type != self._packet_type:
            raise ChordException("Expecting packet type [{}] but got [{}]."\
                .format(self._packet_type, self.packet_type))

    def encode(self):
        nbuf = bytearray()
        nbuf += struct.pack("B", self.packet_type & 0xff)

        self.buf = nbuf

        return nbuf

class ChordRelay(ChordMessage):
    def __init__(self, buf = None):
        self.index = None
        self.packets = None

        super().__init__(CHORD_MSG_RELAY, buf)

    @property
    def for_data(self):
        raise Exception("No more such property.")

    def encode(self):
        nbuf = super().encode()
        nbuf += struct.pack(">L", self.index)

        nbuf += struct.pack(">L", len(self.packets))
        for packet in self.packets:
            nbuf += sshtype.encodeBinary(packet)

        return nbuf

    def parse(self):
        super().parse()
        i = 1
        self.index = struct.unpack(">L", self.buf[i:i+4])[0]
        i += 4

        cnt = struct.unpack(">L", self.buf[i:i+4])[0]
        i += 4
        self.packets = []
        for n in range(cnt):
            l, packet = sshtype.parseBinary(self.buf[i:])
            i += l
            self.packets.append(packet)

class ChordNodeInfo(ChordMessage):
    def __init__(self, buf = None):
        self.sender_address = ""
        self.version = None

        super().__init__(CHORD_MSG_NODE_INFO, buf)

    def encode(self):
        nbuf = super().encode()

        nbuf += sshtype.encodeString(self.sender_address)
        nbuf += sshtype.encodeString(self.version)

        return nbuf

    def parse(self):
        super().parse()

        i = 1
        i, self.sender_address = sshtype.parse_string_from(self.buf, i)
        if i == len(self.buf):
            return
        if len(self.buf) - i > 64:
            raise ChordException("Version string in packet is too long.")
        i, self.version = sshtype.parse_string_from(self.buf, i)

class ChordGetPeers(ChordMessage):
    def __init__(self, buf = None):
        self.sender_port = None

        super().__init__(CHORD_MSG_GET_PEERS, buf)

    def encode(self):
        nbuf = super().encode()

        nbuf += struct.pack(">L", self.sender_port)

        return nbuf

    def parse(self):
        super().parse()

        i = 1
        self.sender_port = struct.unpack(">L", self.buf[i:i+4])[0]

class ChordPeerList(ChordMessage):
    def __init__(self, buf=None, peers=None):
        self.peers = peers # [peer.Peer or db.Peer]

        super().__init__(CHORD_MSG_PEER_LIST, buf)

    def encode(self):
        nbuf = super().encode()
        nbuf += struct.pack(">L", len(self.peers))
        for peer in self.peers:
            nbuf += sshtype.encodeString(peer.address)
            nbuf += sshtype.encodeBinary(peer.node_id)
            if type(peer) is mnpeer.Peer:
                nbuf += sshtype.encodeBinary(peer.node_key.asbytes())
            else:
                assert type(peer) is Peer
                nbuf += sshtype.encodeBinary(peer.pubkey)

        return nbuf

    def parse(self):
        super().parse()
        i = 1
        pcnt = struct.unpack(">L", self.buf[i:i+4])[0]
        i += 4
        self.peers = []
        for n in range(pcnt):
            if log.isEnabledFor(logging.DEBUG):
                log.debug("Reading record {}.".format(n))
            peer = Peer() # db.Peer.
            l, peer.address = sshtype.parseString(self.buf[i:])
            i += l
            l, peer.node_id = sshtype.parseBinary(self.buf[i:])
            i += l
            l, peer.pubkey = sshtype.parseBinary(self.buf[i:])
            i += l

            self.peers.append(peer)

class ChordFindNode(ChordMessage):
    def __init__(self, buf = None):
        self.node_id = None
        self.data_mode = DataMode.none
        self.version = None
        self.significant_bits = None
        self.target_key = None

        super().__init__(CHORD_MSG_FIND_NODE, buf)

    def encode(self):
        nbuf = super().encode()
        nbuf += sshtype.encodeBinary(self.node_id)
        nbuf += struct.pack("B", self.data_mode.value)

        nbuf += struct.pack("?", self.version is not None)
        if self.version is not None:
            nbuf += sshtype.encodeMpint(self.version)

        if self.significant_bits:
            nbuf += struct.pack(">H", self.significant_bits)
            if self.target_key:
                nbuf += sshtype.encodeBinary(self.target_key)

        return nbuf

    def parse(self):
        super().parse()
        i = 1
        l, self.node_id = sshtype.parseBinary(self.buf[i:])
        i += l
        self.data_mode = DataMode(struct.unpack("B", self.buf[i:i+1])[0])
        i += 1

        has_version = struct.unpack_from("?", self.buf, i)[0]
        i += 1
        if has_version:
            i, self.version = sshtype.parse_mpint_from(self.buf, i)

        if i == len(self.buf):
            return

        self.significant_bits = struct.unpack(">H", self.buf[i:i+2])[0]
        i += 2

        if i == len(self.buf):
            return

        i, self.target_key = sshtype.parse_binary_from(self.buf, i)

class ChordGetData(ChordMessage):
    def __init__(self, buf = None):
        super().__init__(CHORD_MSG_GET_DATA, buf)

    def encode(self):
        nbuf = super().encode()

        return nbuf

    def parse(self):
        super().parse()

class ChordDataResponse(ChordMessage):
    def __init__(self, buf = None):
        self.data = None
        self.original_size = 0 # Original (unencrypted) length.
        self.version = None
        self.signature = None
        self.epubkey = None
        self.pubkeylen = None

        super().__init__(CHORD_MSG_DATA_RESPONSE, buf)

    def encode(self):
        nbuf = super().encode()
        nbuf += sshtype.encodeBinary(self.data)
        nbuf += struct.pack(">L", self.original_size)

        if self.version is not None:
            nbuf += sshtype.encodeMpint(self.version)
            nbuf += sshtype.encodeBinary(self.signature)
            if self.epubkey:
                nbuf += sshtype.encodeBinary(self.epubkey)
                nbuf += struct.pack(">L", self.pubkeylen)

        return nbuf

    def parse(self):
        super().parse()
        i = 1
        l, self.data = sshtype.parseBinary(self.buf[i:])
        i += l
        self.original_size = struct.unpack(">L", self.buf[i:i+4])[0]
        i += 4

        if i == len(self.buf):
            return

        l, self.version = sshtype.parseMpint(self.buf[i:])
        i += l
        l, self.signature = sshtype.parseBinary(self.buf[i:])
        i += l

        if i == len(self.buf):
            return

        l, self.epubkey = sshtype.parseBinary(self.buf[i:])
        i += l
        self.pubkeylen = struct.unpack(">L", self.buf[i:i+4])[0]

class ChordDataPresence(ChordMessage):
    def __init__(self, buf = None):
        self.data_present = False
        self.first_id = None

        super().__init__(CHORD_MSG_DATA_PRESENCE, buf)

    def encode(self):
        nbuf = super().encode()
        if self.first_id is None:
            nbuf += struct.pack("?", self.data_present)
        else:
            nbuf += sshtype.encodeBinary(self.first_id)

        return nbuf

    def parse(self):
        super().parse()
        i = 1

        if i + 1 == len(self.buf):
            self.data_present = struct.unpack("?", self.buf[i:i+1])[0]
        else:
            l, self.first_id = sshtype.parseBinary(self.buf[i:])

class ChordStoreData(ChordMessage):
    def __init__(self, buf = None):
        self.data = None
        self.targeted = False

        self.pubkey = None
        self.path_hash = None
        self.version = None
        self.signature = None

        super().__init__(CHORD_MSG_STORE_DATA, buf)

    @property
    def data_id(self):
        raise Exception("No more such property.")

    def encode(self):
        nbuf = super().encode()
        nbuf += sshtype.encodeBinary(self.data)
        nbuf += struct.pack("?", self.targeted)

        if self.pubkey:
            # Updateable keys.
            nbuf += sshtype.encodeBinary(self.pubkey)
            nbuf += sshtype.encodeBinary(self.path_hash)
            nbuf += sshtype.encodeMpint(self.version)
            nbuf += sshtype.encodeBinary(self.signature)

        return nbuf

    def parse(self):
        super().parse()
        i = 1
        l, self.data = sshtype.parseBinary(self.buf[i:])
        i += l
        self.targeted = struct.unpack_from("?", self.buf, i)[0]
        i += 1

        if i == len(self.buf):
            return

        l, self.pubkey = sshtype.parseBinary(self.buf[i:])
        i += l
        l, self.path_hash = sshtype.parseBinary(self.buf[i:])
        i += l
        l, self.version = sshtype.parseMpint(self.buf[i:])
        i += l
        l, self.signature = sshtype.parseBinary(self.buf[i:])

class ChordStoreKey(ChordMessage):
    def __init__(self, buf = None):
        self.data = None
        self.targeted = False

        super().__init__(CHORD_MSG_STORE_KEY, buf)

    def encode(self):
        nbuf = super().encode()
        nbuf += sshtype.encodeBinary(self.data)
        nbuf += struct.pack("?", self.targeted)

        return nbuf

    def parse(self):
        super().parse()
        i = 1
        l, self.data = sshtype.parseBinary(self.buf[i:])
        i += l
        self.targeted = struct.unpack_from("?", self.buf, i)[0]

class ChordDataStored(ChordMessage):
    def __init__(self, buf = None):
        self.stored = False

        super().__init__(CHORD_MSG_DATA_STORED, buf)

    def encode(self):
        nbuf = super().encode()
        nbuf += struct.pack("?", self.stored)

        return nbuf

    def parse(self):
        super().parse()
        i = 1
        self.stored = struct.unpack("?", self.buf[i:i+1])[0]

class ChordStorageInterest(ChordMessage):
    def __init__(self, buf = None):
        self.will_store = False

        super().__init__(CHORD_MSG_STORAGE_INTEREST, buf)

    def encode(self):
        nbuf = super().encode()
        nbuf += struct.pack("?", self.will_store)

        return nbuf

    def parse(self):
        super().parse()
        i = 1
        self.will_store = struct.unpack("?", self.buf[i:i+1])[0]
