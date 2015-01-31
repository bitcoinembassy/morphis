import llog

import struct
import logging

import sshtype

SSH_MSG_DISCONNECT = 1
SSH_MSG_IGNORE = 2
SSH_MSG_UNIMPLEMENTED = 3
SSH_MSG_DEBUG = 4
SSH_MSG_SERVICE_REQUEST = 5
SSH_MSG_SERVICE_ACCEPT = 6
SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21

log = logging.getLogger(__name__)

class SshPacket():
    def __init__(self, packet_type = None, buf = None):
        if buf == None:
            self.setPacketType(packet_type)
            self.buf = None
            return

        self.buf = buf
        self.parse();

        if packet_type != None and self.getPacketType() != packet_type:
            raise Exception("Expecting packet type [{}] but got [{}].".format(packet_type, self.getPacketType()))

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
        super().__init__(20, buf)

        if buf == None:
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
        super().__init__(30, buf)

        if buf == None:
            self.e = None

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
        super().__init__(31, buf)

        if buf == None:
            self.host_key = None
            self.f = None
            self.signature = None

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

class SshNewKeysMessage(SshPacket):
    def __init__(self, buf = None):
        super().__init__(SSH_MSG_NEWKEYS, buf)

    def encode(self):
        nbuf = bytearray()

        nbuf += struct.pack("B", self.getPacketType() & 0xff)

        self.buf = nbuf

class SshServiceRequestMessage(SshPacket):
    def __init__(self, buf = None):
        super().__init__(SSH_MSG_SERVICE_REQUEST, buf)

        if buf == None:
            self.service_name = None

    def get_service_name(self):
        return self.service_name

    def parse(self):
        super().parse()

        i = 1
        l, self.service_name = sshtype.parseString(self.buf[i:])

    def encode(self):
        nbuf += struct.pack("B", self.getPacketType() & 0xff)
        nbuf += sshtype.encodeString(self.service_name)

        self.buf = nbuf

class SshServiceAcceptMessage(SshPacket):
    def __init__(self, buf = None):
        super().__init__(SSH_MSG_SERVICE_ACCEPT, buf)

    def parse(self):
        super().parse()

        i = 1
        l, self.service_name = sshtype.parseString(self.buf[i:])

    def encode(self):
        nbuf += struct.pack("B", self.getPacketType() & 0xff)
        nbuf += sshtype.encodeString(self.service_name)

        self.buf = nbuf

class SshDisconnectMessage(SshPacket):
    def __init__(self, buf = None):
        super().__init__(SSH_MSG_DISCONNECT, buf)

    def parse(self):
        super().parse()

        i = 1
        self.reason_code = struct.unpack(">L", self.buf[i:i+4])[0]
        i += 4
        l, self.description = sshtype.parseString(self.buf[i:])
        i += l
        l, self.language_code = sshtype.parseString(self.buf[i:])

    def encode(self):
        nbuf += struct.pack("B", self.getPacketType() & 0xff)
        nbuf += struct.pack(">L", self.self.reason_code)
        nbuf += sshtype.encodeString(self.description)
        nbuf += sshtype.encodeString(self.language_tag)

        self.buf = nbuf

