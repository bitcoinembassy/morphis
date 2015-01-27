import llog

import struct
import logging

import sshtype

log = logging.getLogger(__name__)

class SshPacket():
    def __init__(self, buf = None):
        if buf == None:
            self.buf = None
            return

        self.buf = buf

        self.parse();

    def parse(self):
        self.packetType = struct.unpack("B", self.buf[0:1])[0]

    def getBuf(self):
        return self.buf

    def setPacketType(self, packetType):
        self.packetType = packetType

    def getPacketType(self):
        return self.packetType

class SshKexInitMessage(SshPacket):
    def __init__(self, buf = None):
        super().__init__(buf)

        packet_type = 20
        if buf == None:
            self.setPacketType(packet_type)
            self.kex_algorithms = ""
            self.server_host_key_algorithms = ""
            self.encryption_algorithms_client_to_server = ""
            self.encryption_algorithms_server_to_client = ""
            self.mac_algorithms_client_to_server = ""
            self.mac_algorithms_server_to_client = ""
            self.compression_algorithms_client_to_server = ""
            self.compression_algorithms_server_to_client = ""
            self.languages_client_to_server = ""
            self.languages_server_to_client = ""
            self.first_kex_packet_follows = ""
        else:
            if (self.getPacketType() != packet_type):
                raise Exception("Expecting packet type [{}] but got [{}].".format(packet_type, self.getPacketType()))

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

        nbuf += sshtype.encodeNameList(self.server_host_key_algorithms)
        nbuf += sshtype.encodeNameList(self.encryption_algorithms_client_to_server)
        nbuf += sshtype.encodeNameList(self.encryption_algorithms_server_to_client)
        nbuf += sshtype.encodeNameList(self.mac_algorithms_client_to_server)
        nbuf += sshtype.encodeNameList(self.mac_algorithms_server_to_client)
        nbuf += sshtype.encodeNameList(self.compression_algorithms_client_to_server)
        nbuf += sshtype.encodeNameList(self.compression_algorithms_server_to_client)
        nbuf += sshtype.encodeNameList(self.languages_client_to_server)
        nbuf += sshtype.encodeNameList(self.languages_server_to_client)
        nbuf += struct.pack("?", self.first_kex_packet_follows)
        nbuf += struct.pack(">L", 0)

        self.buf = nbuf

    def getCookie(self):
        return self.cookie

    def getKeyExchangeAlgorithms(self):
        return self.kex_algorithms

    def setCookie(self, cookie):
        self.cookie = cookie

    def setKeyExchangeAlgorithms(self, value):
        self.kex_algorithms = value

    def setServerHostKeyAlgorithms(self, value):
        self.server_host_key_algorithms = value

    def setEncryptionAlgorithmsClientToServer(self, value):
        self.encryption_algorithms_client_to_server = value

    def setEncryptionAlgorithmsServerToClient(self, value):
        self.encryption_algorithms_server_to_client = value

    def setMacAlgorithmsClientToServer(self, value):
        self.mac_algorithms_client_to_server = value

    def setMacAlgorithmsServerToClient(self, value):
        self.mac_algorithms_server_to_client = value

    def setCompressionAlgorithmsClientToServer(self, value):
        self.compression_algorithms_server_to_client = value

    def setCompressionAlgorithmsServerToClient(self, value):
        self.compression_algorithms_client_to_server = value

class SshKexdhInitMessage(SshPacket):
    def __init__(self, buf = None):
        super().__init__(buf)

        packet_type = 30
        if buf == None:
            self.setPacketType(packet_type)
            self.e = None
        else:
            if (self.getPacketType() != packet_type):
                raise Exception("Expecting packet type [{}] but got [{}].".format(packet_type, self.getPacketType()))

    def getE(self):
        return self.e

    def setE(self, e):
        self.e = e

    def parse(self):
        super().parse()

        self.e = sshtype.parseMpint(self.buf[1:])[1]

    def encode(self):
        nbuf = bytearray()

        nbuf += struct.pack("B", self.getPacketType() & 0xff)
        nbuf += sshtype.encodeMpint(self.e)

        self.buf = nbuf

class SshKexdhReplyMessage(SshPacket):
    def __init__(self, buf = None):
        super().__init__(buf)

        packet_type = 31
        if buf == None:
            self.setPacketType(packet_type)
            self.host_key = None
            self.f = None
            self.signature = None
        else:
            if (self.getPacketType() != packet_type):
                raise Exception("Expecting packet type [{}] but got [{}].".format(packet_type, self.getPacketType()))

    def getHostKey(self):
        return self.host_key

    def setHostKey(self, val):
        self.host_key = val

    def getF(self):
        return self.f

    def setF(self, f):
        self.f = f

    def getSignature(self):
        return self.signature

    def setSignature(self, val):
        self.signature = val

    def parse(self):
        super().parse()

        i = 1
        l, self.host_key = sshtype.parseBinary(self.buf[i:])
        i += l
        l, self.f = sshtype.parseMpint(self.buf[i:])
        i += l
        l, self.signature = sshtype.parseBinary(self.buf[i:])

    def encode(self):
        nbuf = bytearray()

        nbuf += struct.pack("B", self.getPacketType() & 0xff)
        nbuf += sshtype.encodeBinary(self.host_key)
        nbuf += sshtype.encodeMpint(self.f)
        nbuf += sshtype.encodeBinary(self.signature)

        self.buf = nbuf
