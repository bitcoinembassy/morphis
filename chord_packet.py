import llog

import logging
import struct

from chordexception import ChordException
from db import Peer
import peer as mnpeer
import sshtype

# Chord Message Types.
CHORD_MSG_NODE_INFO = 100
CHORD_MSG_GET_PEERS = 110
CHORD_MSG_PEER_LIST = 115
CHORD_MSG_FIND_NODE = 150
CHORD_MSG_STORE_DATA = 170
CHORD_MSG_STORAGE_INTEREST = 175
CHORD_MSG_RELAY = 160

log = logging.getLogger(__name__)

class ChordMessage(object):
    @staticmethod
    def parse_type(buf):
        return struct.unpack("B", buf[0:1])[0]

    def __init__(self, packet_type = None, buf = None):
        self.buf = buf
        self.packet_type = packet_type

        if not buf:
            return

        self.parse()

        if packet_type and self.packet_type != packet_type:
            raise ChordException("Expecting packet type [{}] but got [{}].".format(packet_type, self.packet_type))

    def parse(self):
        self.packet_type = struct.unpack("B", self.buf[0:1])[0]

    def encode(self):
        nbuf = bytearray()
        nbuf += struct.pack("B", self.packet_type & 0xff)

        self.buf = nbuf

        return nbuf

class ChordNodeInfo(ChordMessage):
    def __init__(self, buf = None):
        self.sender_address = ""

        super().__init__(CHORD_MSG_NODE_INFO, buf)

    def encode(self):
        nbuf = super().encode()

        nbuf += sshtype.encodeString(self.sender_address)

        return nbuf

    def parse(self):
        super().parse()

        i = 1
        l, self.sender_address = sshtype.parseString(self.buf[i:])

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
            log.debug("Reading record {}.".format(n))
            peer = Peer()
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
        self.for_data = False

        super().__init__(CHORD_MSG_FIND_NODE, buf)

    def encode(self):
        nbuf = super().encode()
        nbuf += sshtype.encodeBinary(self.node_id)
        nbuf += struct.pack("?", self.for_data)

        return nbuf

    def parse(self):
        super().parse()
        i = 1
        l, self.node_id = sshtype.parseBinary(self.buf[i:])
        i += l
        self.for_data = struct.unpack("?", self.buf[i:i+1])[0]

class ChordStoreData(ChordMessage):
    def __init__(self, buf = None):
        self.data_hash = None
        self.data = None

        super().__init__(CHORD_MSG_STORE_DATA, buf)

    def encode(self):
        nbuf = super().encode()
        nbuf += sshtype.encodeBinary(self.data_hash)
        nbuf += sshtype.encodeBinary(self.data)

        return nbuf

    def parse(self):
        super().parse()
        i = 1
        l, self.data_hash = sshtype.parseBinary(self.buf[i:])
        i += l
        l, self.data = sshtype.parseBinary(self.buf[i:])

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

class ChordRelay(ChordMessage):
    def __init__(self, buf = None):
        self.index = None
        self.for_data = False
        self.packets = None

        super().__init__(CHORD_MSG_RELAY, buf)

    def encode(self):
        nbuf = super().encode()
        nbuf += struct.pack(">L", self.index)
        nbuf += struct.pack("?", self.for_data)

        nbuf += struct.pack(">L", len(self.packets))
        for packet in self.packets:
            nbuf += sshtype.encodeBinary(packet)

        return nbuf

    def parse(self):
        super().parse()
        i = 1
        self.index = struct.unpack(">L", self.buf[i:i+4])[0]
        i += 4
        self.for_data = struct.unpack("?", self.buf[i:i+1])[0]
        i += 1

        cnt = struct.unpack(">L", self.buf[i:i+4])[0]
        i += 4
        self.packets = []
        for n in range(cnt):
            l, packet = sshtype.parseBinary(self.buf[i:])
            i += l
            self.packets.append(packet)
