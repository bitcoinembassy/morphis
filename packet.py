# Copyright (c) 2014-2015  Sam Maloney.
# License: LGPL

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

SSH_MSG_CHANNEL_IMPLICIT_WRAPPER = 200

log = logging.getLogger(__name__)

class SshPacket():
    @staticmethod
    def parse_type(buf, offset=0):
        return struct.unpack_from("B", buf, offset)[0]

    def __init__(self, packet_type=None, buf=None, offset=0):
        self.buf = buf
        self.packet_type = packet_type

        if not buf:
            return

        self._packet_type = packet_type # Expected packet_type.

        self.offset = offset

        self.parse();

    def parse(self):
        offset = self.offset

        self.packet_type = struct.unpack_from("B", self.buf, offset)[0]

        if self._packet_type and self.packet_type != self._packet_type:
            raise Exception("Expecting packet type [{}] but got [{}]."\
                .format(self._packet_type, self.packet_type))

        return offset + 1

    def encode(self):
        nbuf = bytearray()
        nbuf += struct.pack("B", self.packet_type & 0xFF)

        self.buf = nbuf

        return nbuf

class SshKexInitMessage(SshPacket):
    def __init__(self, buf = None):
        if buf == None:
            self.cookie = None
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

        super().__init__(SSH_MSG_KEXINIT, buf)

    def parse(self):
        super().parse()

        i = 17;
        self.cookie = self.buf[1:i]

        l, v = sshtype.parseNameList(self.buf[i:])
        self.kex_algorithms = v
        i += l

    def encode(self):
        nbuf = super().encode()

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

        return nbuf

class SshKexdhInitMessage(SshPacket):
    def __init__(self, buf = None):
        if buf == None:
            self.e = None

        super().__init__(30, buf)

    def getE(self):
        return self.e

    def setE(self, e):
        self.e = e

    def parse(self):
        super().parse()

        self.e = sshtype.parseMpint(self.buf[1:])[1]

    def encode(self):
        nbuf = super().encode()

        nbuf += sshtype.encodeMpint(self.e)

        return nbuf

class SshKexdhReplyMessage(SshPacket):
    def __init__(self, buf = None):
        if buf == None:
            self.host_key = None
            self.f = None
            self.signature = None

        super().__init__(31, buf)

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
        nbuf = super().encode()

        nbuf += sshtype.encodeBinary(self.host_key)
        nbuf += sshtype.encodeMpint(self.f)
        nbuf += sshtype.encodeBinary(self.signature)

        return nbuf

class SshNewKeysMessage(SshPacket):
    def __init__(self, buf = None):
        super().__init__(SSH_MSG_NEWKEYS, buf)

    def encode(self):
        nbuf = super().encode()
        return nbuf

class SshServiceRequestMessage(SshPacket):
    def __init__(self, buf = None):
        if buf == None:
            self.service_name = None

        super().__init__(SSH_MSG_SERVICE_REQUEST, buf)

    def parse(self):
        super().parse()

        i = 1
        l, self.service_name = sshtype.parseString(self.buf[i:])

    def encode(self):
        nbuf = super().encode()

        nbuf += sshtype.encodeString(self.service_name)

        return nbuf

class SshServiceAcceptMessage(SshPacket):
    def __init__(self, buf = None):
        if buf == None:
            self.service_name = None

        super().__init__(SSH_MSG_SERVICE_ACCEPT, buf)

    def parse(self):
        super().parse()

        i = 1
        l, self.service_name = sshtype.parseString(self.buf[i:])

    def encode(self):
        nbuf = super().encode()

        nbuf += sshtype.encodeString(self.service_name)

        return nbuf

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
        nbuf = super().encode()

        nbuf += struct.pack(">L", self.self.reason_code)
        nbuf += sshtype.encodeString(self.description)
        nbuf += sshtype.encodeString(self.language_tag)

        return nbuf

class SshUserauthRequestMessage(SshPacket):
    def __init__(self, buf = None):
        if buf == None:
            self.user_name = None
            self.service_name = None
            self.method_name = None

        super().__init__(SSH_MSG_USERAUTH_REQUEST, buf)

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
        nbuf = super().encode()

        nbuf += sshtype.encodeString(self.user_name)
        nbuf += sshtype.encodeString(self.service_name)
        nbuf += sshtype.encodeString(self.method_name)
        
        if self.method_name == "publickey":
            nbuf += struct.pack("B", self.signature_present)
            nbuf += sshtype.encodeString(self.algorithm_name)
            nbuf += sshtype.encodeBinary(self.public_key)
            # Leave signature for caller to append, as they need this encoded
            # data to sign.

        return nbuf

class SshUserauthFailureMessage(SshPacket):
    def __init__(self, buf = None):
        if buf == None:
            self.auths = None
            self.partial_success = None

        super().__init__(SSH_MSG_USERAUTH_FAILURE, buf)

    def parse(self):
        super().parse()

        i = 1
        l, self.auths = sshtype.parseNamelist(self.buf[i:])
        i += l
        self.partial_success = struct.decode("?", self.buf[i:])

    def encode(self):
        nbuf = super().encode()

        nbuf += sshtype.encodeNameList(self.auths)
        nbuf += struct.pack("?", self.partial_success)

        return nbuf

class SshUserauthSuccessMessage(SshPacket):
    def __init__(self, buf = None):
        super().__init__(SSH_MSG_USERAUTH_SUCCESS, buf)

    def parse(self):
        super().parse()

    def encode(self):
        nbuf = super().encode()
        return nbuf

class SshUserauthPkOkMessage(SshPacket):
    def __init__(self, buf = None):
        super().__init__(SSH_MSG_USERAUTH_PK_OK, buf)

    def parse(self):
        super().parse()

        i = 1
        l, self.algorithm_name = sshtype.parseString(self.buf[i:])
        i += l
        l, self.public_key = sshtype.parseBinary(self.buf[i:])

    def encode(self):
        nbuf = super().encode()

        nbuf += sshtype.encodeString(self.algorithm_name)
        nbuf += sshtype.encodeBinary(self.public_key)

        return nbuf

class SshChannelOpenMessage(SshPacket):
    def __init__(self, buf = None):
        self.data_packet = None

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

        if i < len(self.buf):
            self.data_packet = self.buf[i:]

    def encode(self):
        nbuf = super().encode()

        nbuf += sshtype.encodeString(self.channel_type)
        nbuf += struct.pack(">L", self.sender_channel)
        nbuf += struct.pack(">L", self.initial_window_size)
        nbuf += struct.pack(">L", self.maximum_packet_size)

        if self.data_packet:
            nbuf += self.data_packet

        return nbuf

class SshChannelOpenConfirmationMessage(SshPacket):
    def __init__(self, buf = None):
        super().__init__(SSH_MSG_CHANNEL_OPEN_CONFIRMATION, buf)

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
        nbuf = super().encode()

        nbuf += struct.pack(">L", self.recipient_channel)
        nbuf += struct.pack(">L", self.sender_channel)
        nbuf += struct.pack(">L", self.initial_window_size)
        nbuf += struct.pack(">L", self.maximum_packet_size)

        return nbuf

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
        nbuf = super().encode()

        nbuf += struct.pack(">L", self.recipient_channel)
        nbuf += struct.pack(">L", self.reason_code)
        nbuf += sshtype.encodeString(self.description)
        nbuf += sshtype.encodeString(self.language_tag)

        return nbuf

class SshChannelCloseMessage(SshPacket):
    def __init__(self, buf = None):
        self.recipient_channel = None
        self.implicit_channel = False

        super().__init__(SSH_MSG_CHANNEL_CLOSE, buf)

    def parse(self):
        super().parse()

        i = 1
        self.recipient_channel = struct.unpack(">L", self.buf[i:i+4])[0]
        i += 4
        if i < len(self.buf):
            self.implicit_channel = struct.unpack("?", self.buf[i:i+1])[0]

    def encode(self):
        nbuf = super().encode()

        nbuf += struct.pack(">L", self.recipient_channel)
        if self.implicit_channel:
            nbuf += struct.pack("?", self.implicit_channel)

        return nbuf

class SshChannelDataMessage(SshPacket):
    def __init__(self, buf=None, offset=0):
        self.recipient_channel = None
        self.data = None

        super().__init__(SSH_MSG_CHANNEL_DATA, buf, offset)

    def parse(self):
        i = super().parse()

        self.recipient_channel = struct.unpack_from(">L", self.buf, i)[0]
        i += 4
        self.data = self.buf[i:]

    def encode(self):
        nbuf = super().encode()

        nbuf += struct.pack(">L", self.recipient_channel)
        if self.data:
            # Allow data to be stored separately.
            nbuf += self.data

        return nbuf

class SshChannelExtendedDataMessage(SshPacket):
    def __init__(self, buf=None, offset=0):
        self.recipient_channel = None
        self.data_type_code = None
        self.data_offset = None

        super().__init__(SSH_MSG_CHANNEL_EXTENDED_DATA, buf, offset)

    def parse(self):
        super().parse()

        i = 1
        self.recipient_channel = struct.unpack_from(">L", self.buf, i)[0]
        i += 4
        self.data_type_code = struct.unpack(">L", self.buf, i)[0]
        i += 4
        self.data_offset = i

    def encode(self):
        nbuf = super().encode()

        nbuf += struct.pack(">L", self.recipient_channel)
        nbuf += struct.pack(">L", self.data_type_code)
        self.data_offset = len(nbuf)
        if self.data:
            # Allow data to be stored separately.
            nbuf += self.data

        return nbuf

class SshChannelRequest(SshPacket):
    def __init__(self, buf=None, offset=0):
        self.recipient_channel = None
        self.request_type = None
        self.want_reply = False
        self.payload = None

        super().__init__(SSH_MSG_CHANNEL_REQUEST, buf, offset)

    def parse(self):
        i = super().parse()

        self.recipient_channel = struct.unpack(">L", self.buf[i:i+4])[0]
        i += 4
        l, self.request_type = sshtype.parseString(self.buf[i:])
        i += l
        self.want_reply = struct.unpack("?", self.buf[i:i+1])[0]
        i += 1

        if i == len(self.buf):
            return
        self.payload = self.buf[i:]

    def encode(self):
        nbuf = super().encode()

        nbuf += struct.pack(">L", self.recipient_channel)
        nbuf += sshtype.encodeString(self.request_type)
        nbuf += struct.pack("?", self.want_reply)
        if self.payload:
            nbuf += self.payload

        return nbuf

class SshChannelImplicitWrapper(SshPacket):
    data_offset = 1

    def __init__(self, buf=None, offset=0):
        super().__init__(SSH_MSG_CHANNEL_IMPLICIT_WRAPPER, buf, offset)
