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

SSH_MSG_USERAUTH_REQUEST = 50
SSH_MSG_USERAUTH_FAILURE = 51
SSH_MSG_USERAUTH_SUCCESS = 52
SSH_MSG_USERAUTH_BANNER = 53

SSH_MSG_USERAUTH_PK_OK = 60

SSH_MSG_GLOBAL_REQUEST = 80
SSH_MSG_REQUEST_SUCCESS = 81
SSH_MSG_REQUEST_FAILURE = 82
SSH_MSG_CHANNEL_OPEN = 90
SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91
SSH_MSG_CHANNEL_OPEN_FAILURE = 92
SSH_MSG_CHANNEL_WINDOW_ADJUST = 93
SSH_MSG_CHANNEL_DATA = 94
SSH_MSG_CHANNEL_EXTENDED_DATA = 95
SSH_MSG_CHANNEL_EOF = 96
SSH_MSG_CHANNEL_CLOSE = 97
SSH_MSG_CHANNEL_REQUEST = 98
SSH_MSG_CHANNEL_SUCCESS = 99
SSH_MSG_CHANNEL_FAILURE = 100

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

    def get_buf(self):
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

    def set_service_name(self, value):
        self.service_name = value

    def parse(self):
        super().parse()

        i = 1
        l, self.service_name = sshtype.parseString(self.buf[i:])

    def encode(self):
        nbuf = bytearray()

        nbuf += struct.pack("B", self.getPacketType() & 0xff)
        nbuf += sshtype.encodeString(self.service_name)

        self.buf = nbuf

class SshServiceAcceptMessage(SshPacket):
    def __init__(self, buf = None):
        super().__init__(SSH_MSG_SERVICE_ACCEPT, buf)

        if buf == None:
            self.service_name = None

    def get_service_name(self):
        return self.service_name

    def set_service_name(self, value):
        self.service_name = value

    def parse(self):
        super().parse()

        i = 1
        l, self.service_name = sshtype.parseString(self.buf[i:])

    def encode(self):
        nbuf = bytearray()

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
        nbuf = bytearray()

        nbuf += struct.pack("B", self.getPacketType() & 0xff)
        nbuf += struct.pack(">L", self.self.reason_code)
        nbuf += sshtype.encodeString(self.description)
        nbuf += sshtype.encodeString(self.language_tag)

        self.buf = nbuf

class SshUserauthRequestMessage(SshPacket):
    def __init__(self, buf = None):
        super().__init__(SSH_MSG_USERAUTH_REQUEST, buf)

        if buf == None:
            self.user_name = None
            self.service_name = None
            self.method_name = None

    def get_user_name(self):
        return self.user_name

    def set_user_name(self, value):
        self.user_name = value

    def get_service_name(self):
        return self.service_name

    def set_service_name(self, value):
        self.service_name = value

    def get_method_name(self):
        return self.method_name

    def set_method_name(self, value):
        self.method_name = value

    def get_signature_present(self):
        return self.signature_present

    def set_signature_present(self, value):
        self.signature_present = value

    def get_algorithm_name(self):
        return self.algorithm_name

    def set_algorithm_name(self, value):
        self.algorithm_name = value

    def get_public_key(self):
        return self.public_key

    def set_public_key(self, value):
        self.public_key = value

    def get_signature(self):
        return self.signature

    def set_signature(self, value):
        self.signature = value

    def get_signature_length(self):
        return self.signature_length

    def parse(self):
        super().parse()

        i = 1
        l, self.user_name = sshtype.parseString(self.buf[i:])
        i += l
        l, self.service_name = sshtype.parseString(self.buf[i:])
        i += l
        l, self.method_name = sshtype.parseString(self.buf[i:])
        i += l

        if self.method_name == "publickey":
            self.signature_present = struct.unpack("?", self.buf[i:i+1])[0]
            i += 1
            l, self.algorithm_name = sshtype.parseString(self.buf[i:])
            i += l
            l, self.public_key = sshtype.parseBinary(self.buf[i:])
            if self.signature_present:
                i += l
                l, self.signature = sshtype.parseBinary(self.buf[i:])
                self.signature_length = l

    def encode(self):
        nbuf = bytearray()

        nbuf += struct.pack("B", self.getPacketType() & 0xff)
        nbuf += sshtype.encodeString(self.user_name)
        nbuf += sshtype.encodeString(self.service_name)
        nbuf += sshtype.encodeString(self.method_name)
        
        if self.method_name == "publickey":
            nbuf += struct.pack("B", self.signature_present)
            nbuf += sshtype.encodeString(self.algorithm_name)
            nbuf += sshtype.encodeBinary(self.public_key)
            # Leave signature for caller to append, as they need this encoded
            # data to sign.

        self.buf = nbuf

class SshUserauthFailureMessage(SshPacket):
    def __init__(self, buf = None):
        super().__init__(SSH_MSG_USERAUTH_FAILURE, buf)

        if buf == None:
            self.auths = None
            self.partial_success = None

    def get_auths(self):
        return self.auths

    def set_auths(self, val):
        self.auths = val

    def get_partial_success(self):
        return self.partial_success

    def set_partial_success(self, val):
        self.partial_success = val

    def parse(self):
        super().parse()

        i = 1
        l, self.auths = sshtype.parseNamelist(self.buf[i:])
        i += l
        self.partial_success = struct.decode("?", self.buf[i:])

    def encode(self):
        nbuf = bytearray()

        nbuf += struct.pack("B", self.getPacketType() & 0xff)
        nbuf += sshtype.encodeNameList(self.auths)
        nbuf += struct.pack("?", self.partial_success)

        self.buf = nbuf

class SshUserauthSuccessMessage(SshPacket):
    def __init__(self, buf = None):
        super().__init__(SSH_MSG_USERAUTH_SUCCESS, buf)

    def parse(self):
        super().parse()

    def encode(self):
        nbuf = bytearray()

        nbuf += struct.pack("B", self.getPacketType() & 0xff)

        self.buf = nbuf

class SshUserauthPkOkMessage(SshPacket):
    def __init__(self, buf = None):
        super().__init__(SSH_MSG_USERAUTH_PK_OK, buf)

    def get_algorithm_name(self):
        return self.algorithm_name

    def set_algorithm_name(self, value):
        self.algorithm_name = value

    def get_public_key(self):
        return self.public_key

    def set_public_key(self, value):
        self.public_key = value

    def parse(self):
        super().parse()

        i = 1
        l, self.algorithm_name = sshtype.parseString(self.buf[i:])
        i += l
        l, self.public_key = sshtype.parseBinary(self.buf[i:])

    def encode(self):
        nbuf = bytearray()

        nbuf += struct.pack("B", self.getPacketType() & 0xff)
        nbuf += sshtype.encodeString(self.algorithm_name)
        nbuf += sshtype.encodeBinary(self.public_key)

        self.buf = nbuf

class SshChannelOpenMessage(SshPacket):
    def __init__(self, buf = None):
        super().__init__(SSH_MSG_CHANNEL_OPEN, buf)

    def parse(self):
        super().parse()

        i = 1
        l, self.channel_type = sshtype.parseString(self.buf[i:])
        i += l
        self.sender_channel = struct.unpack(">L", self.buf[i:i+4])[0]
        i += 4
        self.initial_window_size = struct.unpack(">L", self.buf[i:i+4])[0]
        i += 4
        self.maximum_packet_size = struct.unpack(">L", self.buf[i:i+4])[0]
        i += 4

    def encode(self):
        nbuf = bytearray()

        nbuf += struct.pack("B", self.getPacketType() & 0xff)
        nbuf += sshtype.encodeString(self.channel_type)
        nbuf += struct.pack(">L", self.sender_channel)
        nbuf += struct.pack(">L", self.initial_window_size)
        nbuf += struct.pack(">L", self.maximum_packet_size)

        self.buf = nbuf

class SshChannelOpenConfirmationMessage(SshPacket):
    def __init__(self, buf = None):
        super().__init__(SSH_MSG_CHANNEL_OPEN_CONFIRMATION, buf)

    def get_recipient_channel(self):
        return self.sender_channel

    def set_recipient_channel(self, value):
        self.recipient_channel = value

    def get_sender_channel(self):
        return self.sender_channel

    def set_sender_channel(self, value):
        self.sender_channel = value

    def get_initial_window_size(self):
        return self.initial_window_size

    def set_initial_window_size(self, value):
        self.initial_window_size = value

    def get_maximum_packet_size(self):
        return self.maximum_packet_size

    def set_maximum_packet_size(self, value):
        self.maximum_packet_size = value

    def parse(self):
        super().parse()

        i = 1
        self.recipient_channel = struct.unpack(">L", self.buf[i:i+4])[0]
        i += 4
        self.sender_channel = struct.unpack(">L", self.buf[i:i+4])[0]
        i += 4
        self.initial_window_size = struct.unpack(">L", self.buf[i:i+4])[0]
        i += 4
        self.maximum_packet_size = struct.unpack(">L", self.buf[i:i+4])[0]
        i += 4

    def encode(self):
        nbuf = bytearray()

        nbuf += struct.pack("B", self.getPacketType() & 0xff)
        nbuf += struct.pack(">L", self.recipient_channel)
        nbuf += struct.pack(">L", self.sender_channel)
        nbuf += struct.pack(">L", self.initial_window_size)
        nbuf += struct.pack(">L", self.maximum_packet_size)

        self.buf = nbuf

class SshChannelOpenFailureMessage(SshPacket):
    def __init__(self, buf = None):
        super().__init__(SSH_MSG_CHANNEL_OPEN_FAILURE, buf)

    def parse(self):
        super().parse()

        i = 1
        self.recipient_channel = struct.unpack(">L", self.buf[i:i+4])[0]
        i += 4
        self.reason_code = struct.unpack(">L", self.buf[i:i+4])[0]
        i += 4
        l, self.description = sshtype.parseString(self.buf[i:])
        i += l
        l, self.language_tag = sshtype.parseString(self.buf[i:])

    def encode(self):
        nbuf = bytearray()

        nbuf += struct.pack("B", self.getPacketType() & 0xff)
        nbuf += struct.pack(">L", self.recipient_channel)
        nbuf += struct.pack(">L", self.reason_code)
        nbuf += sshtype.encodeString(self.description)
        nbuf += sshtype.encodeString(self.language_tag)

        self.buf = nbuf

class SshChannelDataMessage(SshPacket):
    def __init__(self, buf = None):
        super().__init__(SSH_MSG_CHANNEL_DATA, buf)

    def get_recipient_channel(self):
        return self.recipient_channel

    def set_recipient_channel(self, value):
        self.recipient_channel = value

    def get_data(self):
        return self.data

    def set_data(self, value):
        self.data = value

    def parse(self):
        super().parse()

        i = 1
        self.recipient_channel = struct.unpack(">L", self.buf[i:i+4])[0]
        i += 4
        self.data = self.buf[i:]

    def encode(self):
        nbuf = bytearray()

        nbuf += struct.pack("B", self.getPacketType() & 0xff)
        nbuf += struct.pack(">L", self.recipient_channel)
        nbuf += self.data

        self.buf = nbuf
