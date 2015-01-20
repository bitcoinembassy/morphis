import llog

import struct
import logging

import sshtype

log = logging.getLogger(__name__)

class MNetPacket():
    def __init__(self, buf = None):
        if buf == None:
            self.buf = None
            return

        self.buf = buf

        self.parse();

    def parse(self):
        self.packetType = struct.unpack("B", self.buf[0:1])[0]

    def setPacketType(self, packetType):
        self.packetType = packetType

    def getPacketType(self):
        return self.packetType

class MNetKexinitMessage(MNetPacket):
    def parse(self):
        super().parse()

        i = 17;
        self.cookie = self.buf[1:i]

        l, v = sshtype.parseNameList(self.buf[i:])
        self.kex_algorithms = v
        i += l

    def encode(self):
        nbuf = bytearray()

        nbuf += struct.pack("B", self.getPacketType() & 0xff)
        nbuf += self.cookie
        nbuf += sshtype.encodeNameList(self.kex_algorithms)

        self.buf = nbuf

    def getCookie(self):
        return self.cookie

    def getKeyExchangeAlgorithms(self):
        return self.kex_algorithms

    def setCookie(self, cookie):
        self.cookie = cookie

    def setKeyExchangeAlgorithms(self, value):
        self.kex_algorithms = value
