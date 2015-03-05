import llog

import asyncio
import struct
import logging
import os

from Crypto.Cipher import AES
from hashlib import sha1
import hmac

import packet as mnetpacket
import kex
import rsakey
import sshtype
from sshexception import *
from mutil import hex_dump
import peer

clientPipes = {} # task, [reader, writer]
clientObjs = {} # remoteAddress, dict

log = logging.getLogger(__name__)

serverKey = None
clientKey = None

# Returns True on success, False on failure.
@asyncio.coroutine
def connectTaskCommon(protocol, serverMode):
#    try:
    r = yield from _connectTaskCommon(protocol, serverMode)
#    except:
#        log.exception("_connectTaskCommon() threw:")

    return r

@asyncio.coroutine
def _connectTaskCommon(protocol, serverMode):
    assert isinstance(serverMode, bool)

    log.info("X: Sending banner.")
    protocol.transport.write((protocol.getLocalBanner() + "\r\n").encode(encoding="UTF-8"))

    # Read banner.
    packet = yield from protocol.read_packet()
    log.info("X: Received banner [{}].".format(packet))

    protocol.setRemoteBanner(packet.decode(encoding="UTF-8"))

    # Send KexInit packet.
    opobj = mnetpacket.SshKexInitMessage()
    opobj.setCookie(os.urandom(16))
#    opobj.setServerHostKeyAlgorithms("ssh-dss")
    opobj.setServerHostKeyAlgorithms("ssh-rsa")
#    opobj.setKeyExchangeAlgorithms("diffie-hellman-group-exchange-sha256")
    opobj.setKeyExchangeAlgorithms("diffie-hellman-group14-sha1")
    opobj.setEncryptionAlgorithmsClientToServer("aes256-cbc")
    opobj.setEncryptionAlgorithmsServerToClient("aes256-cbc")
#    opobj.setMacAlgorithmsClientToServer("hmac-sha2-512")
#    opobj.setMacAlgorithmsServerToClient("hmac-sha2-512")
    opobj.setMacAlgorithmsClientToServer("hmac-sha1")
    opobj.setMacAlgorithmsServerToClient("hmac-sha1")
    opobj.setCompressionAlgorithmsClientToServer("none")
    opobj.setCompressionAlgorithmsServerToClient("none")
    opobj.encode()

    protocol.setLocalKexInitMessage(opobj.getBuf())

    protocol.write_packet(opobj)

    # Read KexInit packet.
    packet = yield from protocol.read_packet()
    log.info("X: Received packet [{}].".format(packet))

    pobj = mnetpacket.SshPacket(None, packet)
    packet_type = pobj.getPacketType()
    log.info("packet_type=[{}].".format(packet_type))

    if packet_type != 20:
        log.warning("Peer sent unexpected packet_type[{}], disconnecting.".format(packet_type))
        protocol.transport.close()
        return False

    protocol.setRemoteKexInitMessage(packet)

    pobj = mnetpacket.SshKexInitMessage(packet)
    log.info("cookie=[{}].".format(pobj.getCookie()))
    log.info("keyExchangeAlgorithms=[{}].".format(pobj.getKeyExchangeAlgorithms()))

    protocol.waitingForNewKeys = True

    ke = kex.KexGroup14(protocol)
    log.info("Calling start_kex()...")
    yield from ke.do_kex()

    # Setup encryption now that keys are exchanged.
    protocol.init_outbound_encryption()

    if not protocol.serverMode:
        """ Server gets done automatically since parameters are always there
            before NEWKEYS is received, but client the parameters and NEWKEYS
            message may come in the same tcppacket, so the auto part just turns
            off inbound processing and waits for us to call
            init_inbound_encryption when we have the parameters ready. """
        protocol.init_inbound_encryption()
        protocol.set_inbound_enabled(True)

    packet = yield from protocol.read_packet()
    m = mnetpacket.SshNewKeysMessage(packet)
    log.debug("Received SSH_MSG_NEWKEYS.")

    if protocol.serverMode:
        packet = yield from protocol.read_packet()
#        m = mnetpacket.SshPacket(None, packet)
#        log.info("X: Received packet (type={}) [{}].".format(m.getPacketType(), packet))
        m = mnetpacket.SshServiceRequestMessage(packet)
        log.info("Service requested [{}].".format(m.get_service_name()))

        if m.get_service_name() != "ssh-userauth":
            raise SshException("Remote end requested unexpected service (name=[{}]).".format(m.get_service_name()))

        mr = mnetpacket.SshServiceAcceptMessage()
        mr.set_service_name("ssh-userauth")
        mr.encode()

        protocol.write_packet(mr)

        packet = yield from protocol.read_packet()
        m = mnetpacket.SshUserauthRequestMessage(packet)
        log.info("Userauth requested with method=[{}].".format(m.get_method_name()))

        if m.get_method_name() == "none":
            mr = mnetpacket.SshUserauthFailureMessage()
            mr.set_auths("publickey")
            mr.set_partial_success(False)
            mr.encode()

            protocol.write_packet(mr)

            packet = yield from protocol.read_packet()
            m = mnetpacket.SshUserauthRequestMessage(packet)
            log.info("Userauth requested with method=[{}].".format(m.get_method_name()))

        if m.get_method_name() != "publickey":
            raise SshException("Unhandled client auth method [{}].".format(m.get_method_name()))
        if m.get_algorithm_name() != "ssh-rsa":
            raise SshException("Unhandled client auth algorithm [{}].".format(m.get_algorithm_name()))

        log.debug("m.signature_present()={}.".format(m.get_signature_present()))

        if not m.get_signature_present():
            mr = mnetpacket.SshUserauthPkOkMessage()
            mr.set_algorithm_name(m.get_algorithm_name())
            mr.set_public_key(m.get_public_key())
            mr.encode()

            protocol.write_packet(mr)

            packet = yield from protocol.read_packet()
            m = mnetpacket.SshUserauthRequestMessage(packet)
            log.info("Userauth requested with method=[{}].".format(m.get_method_name()))

            if m.get_method_name() != "publickey":
                raise SshException("Unhandled client auth method [{}].".format(m.get_method_name()))
            if m.get_algorithm_name() != "ssh-rsa":
                raise SshException("Unhandled client auth algorithm [{}].".format(m.get_algorithm_name()))

        log.debug("signature=[{}].".format(m.get_signature()))

        signature = m.get_signature()

        buf = bytearray()
        buf += sshtype.encodeBinary(protocol.get_session_id())
        buf += packet[:-m.get_signature_length()]

        client_key = rsakey.RsaKey(m.get_public_key())
        r = client_key.verify_ssh_sig(buf, signature)

        log.info("Userauth signature check result: [{}].".format(r))
        if not r:
            raise SshException("Signature and key provided by client did not match.")

        protocol.clientKey = client_key
        protocol.connection_handler.client_authenticated(protocol)

        mr = mnetpacket.SshUserauthSuccessMessage()
        mr.encode()

        protocol.write_packet(mr)
    else:
        m = mnetpacket.SshServiceRequestMessage()
        m.set_service_name("ssh-userauth")
        m.encode()

        protocol.write_packet(m)

        packet = yield from protocol.read_packet()
        m = mnetpacket.SshServiceAcceptMessage(packet)
        log.info("Service request accepted [{}].".format(m.get_service_name()))

        mr = mnetpacket.SshUserauthRequestMessage()
        mr.set_user_name("dev")
        mr.set_service_name("ssh-connection")
        mr.set_method_name("publickey")
        mr.set_signature_present(True)
        mr.set_algorithm_name("ssh-rsa")

        ckey = protocol.get_client_key()
        mr.set_public_key(ckey.asbytes())

        mr.encode()

        mrb = bytearray()
        mrb += sshtype.encodeBinary(protocol.get_session_id())
        mrb += mr.get_buf()

        sig = sshtype.encodeBinary(ckey.sign_ssh_data(mrb))

        mrb = mr.get_buf()
        assert mr.buf == mrb
        mrb += sig

        protocol.write_packet(mr)

        packet = yield from protocol.read_packet()
        m = mnetpacket.SshUserauthSuccessMessage(packet)
        log.info("Userauth accepted.")

    log.debug("Connect task done (server={}).".format(serverMode))

#    if not serverMode:
#        protocol.transport.close()

    return True

@asyncio.coroutine
def clientConnectTask(protocol):
    r = yield from connectTaskCommon(protocol, False)
    if not r:
        return r

class SshProtocol(asyncio.Protocol):
    def __init__(self, loop):
        self.loop = loop

        self.address = None

        self.channel_handler = None
        self.connection_handler = None

        self.serverMode = None

        self.binaryMode = False
        self.inboundEnabled = True

        self.serverKey = serverKey
        self.clientKey = clientKey
        self.k = None
        self.h = None
        self.sessionId = None
        self.inCipher = None
        self.outCipher = None
        self.inHmacKey = None
        self.outHmacKey = None
        self.inHmacSize = 0
        self.outHmacSize = 0
        self.waitingForNewKeys = False

        self.waiter = None
        self.buf = b''
        self.packet = None
        self.bpLength = None

        self.inPacketId = 0
        self.outPacketId = 0

        self.remoteBanner = None
        self.localKexInitMessage = None
        self.remoteKexInitMessage = None

    def set_connection_handler(self, value):
        self.connection_handler = value

    def set_channel_handler(self, value):
        self.channel_handler = value

    def get_transport(self):
        return self.transport

    def get_server_key(self):
        return self.serverKey

    def set_server_key(self, value):
        self.serverKey = value

    def get_client_key(self):
        return self.clientKey

    def set_client_key(self, value):
        self.clientKey = value

    def get_session_id(self):
        return self.sessionId

    def verify_server_key(self, key_data, sig):
        key = rsakey.RsaKey(key_data)

        if not key.verify_ssh_sig(self.h, sig):
            raise SshException("Signature verification failed.")

        log.info("Signature validated correctly!")

        self.serverKey = key

    def set_K_H(self, k, h):
        self.k = k
        self.h = h

        if self.sessionId == None:
            self.sessionId = h

    def set_inbound_enabled(self, val):
        self.inboundEnabled = val

    def getRemoteBanner(self):
        return self.remoteBanner

    def setRemoteBanner(self, val):
        self.remoteBanner = val

    def getLocalBanner(self):
        return "SSH-2.0-mNet_0.0.1"

    def getLocalKexInitMessage(self):
        return self.localKexInitMessage

    def setLocalKexInitMessage(self, val):
        self.localKexInitMessage = val

    def getRemoteKexInitMessage(self):
        return self.remoteKexInitMessage

    def setRemoteKexInitMessage(self, val):
        self.remoteKexInitMessage = val

    def init_outbound_encryption(self):
        log.debug("Initializing outbound encryption.")
        # use: AES.MODE_CBC: bs: 16, ks: 32. hmac-sha1=20 key size.
        if not self.serverMode:
            iiv = self.generateKey(b'A', 16)
            ekey = self.generateKey(b'C', 32)
            ikey = self.generateKey(b'E', 20)
        else:
            iiv = self.generateKey(b'B', 16)
            ekey = self.generateKey(b'D', 32)
            ikey = self.generateKey(b'F', 20)

        log.info("ekey=[{}], iiv=[{}].".format(ekey, iiv))
        self.outCipher = AES.new(ekey, AES.MODE_CBC, iiv)
        self.outHmacKey = ikey
        self.outHmacSize = 20

    def init_inbound_encryption(self):
        log.debug("Initializing inbound encryption.")
        # use: AES.MODE_CBC: bs: 16, ks: 32. hmac-sha1=20 key size.
        if not self.serverMode:
            iiv = self.generateKey(b'B', 16)
            ekey = self.generateKey(b'D', 32)
            ikey = self.generateKey(b'F', 20)
        else:
            iiv = self.generateKey(b'A', 16)
            ekey = self.generateKey(b'C', 32)
            ikey = self.generateKey(b'E', 20)

        log.info("ekey=[{}], iiv=[{}].".format(ekey, iiv))
        self.inCipher = AES.new(ekey, AES.MODE_CBC, iiv)
        self.inHmacKey = ikey
        self.inHmacSize = 20

    def generateKey(self, extra, needed_bytes):
        assert isinstance(extra, bytes) and len(extra) == 1

        buf = bytearray()
        buf += sshtype.encodeMpint(self.k)
        buf += self.h
        buf += extra
        buf += self.sessionId

        r = sha1(buf).digest()

        while len(r) < needed_bytes:
            buf.clear()
            buf += sshtype.encodeMpint(self.k)
            buf += self.h
            buf += r

            r += sha1(buf).digest()

        return r[:needed_bytes]

    def connection_made(self, transport):
        self.transport = transport
        self.address = peer_name = transport.get_extra_info("peername")

        log.debug("P: Connection made with [{}].".format(peer_name))

        self.connection_handler.connection_made(self)

        client = clientObjs.get(peer_name)
        if client == None:
            log.info("P: Initializing new clientObj.")
            client = {"connected": True}
        elif client["connected"]:
            log.warning("P: Already connected with client [{}].".format(client))

        clientObjs[peer_name] = client

        self.client = client

    def data_received(self, data):
        try:
            self._data_received(data)
        except:
            log.exception("_data_received() threw:")

    def error_received(self, exc):
        log.info("X: Error received: {}".format(exc))
        self.connection_handler.error_received(self, exc)

    def connection_lost(self, exc):
        log.info("X: Connection lost to [{}], client=[{}].".format(self.address, self.client))
        self.connection_handler.connection_lost(self, exc)

    def _data_received(self, data):
        log.debug("data_received(..): start.")
        log.info("X: Received: [\n{}].".format(hex_dump(data)))

        if self.binaryMode:
            self.buf += data
            if self.inboundEnabled:
                self.process_buffer()
            log.debug("data_received(..): end (binaryMode).")
            return

        # Handle handshake packet, detect end.
        end = data.find(b"\r\n")
        if end != -1:
            self.buf += data[0:end]
            self.packet = self.buf
            self.buf = data[end+2:]
            self.binaryMode = True

            if self.waiter != None:
                self.waiter.set_result(False)
                self.waiter = None

            # The following would overwrite packet if it were a complete
            # packet in the buf.
#            if len(self.buf) > 0:
#                self.process_buffer()
        else:
            self.buf += data

        log.debug("data_received(..): end.")

    @asyncio.coroutine
    def do_wait(self):
        if self.waiter is not None:
            errmsg = "waiter already set!"
            log.fatal(errmsg)
            raise Exception(errmsg)

        self.waiter = asyncio.futures.Future(loop=self.loop)

        try:
            yield from self.waiter
        finally:
            self.waiter = None

    @asyncio.coroutine
    def read_packet(self):
        if self.packet != None:
            packet = self.packet
            log.info("P: Returning next packet.")
            self.packet = None

            #asyncio.call_soon(self.process_buffer())
            # For now, call process_buffer in this event.
            if len(self.buf) > 0:
                self.process_buffer()

            return packet

        log.info("P: Waiting for packet.")
        yield from self.do_wait()

        assert self.packet != None
        packet = self.packet
        self.packet = None

        # For now, call process_buffer in this event.
        if len(self.buf) > 0:
            self.process_buffer()

        log.info("P: Returning packet.")

        return packet

    def write_packet(self, packetObject):
        length = len(packetObject.getBuf())

        log.debug("Writing packetType=[{}] with [{}] bytes of data: [\n{}]".format(packetObject.getPacketType(), length, hex_dump(packetObject.getBuf())))

        mod_size = None
        if self.outCipher == None:
            mod_size = 8 # RFC says 8 minimum.
        else:
            mod_size = 16 # bs of current cipher is 16.

        extra = (length + 5) % mod_size;
        if extra != 0:
            padding = mod_size - extra
            if padding < 4:
                padding += mod_size #Minimum padding is 4.
        else:
            padding = mod_size; #Minimum padding is 4.

        if self.outCipher == None:
            self.transport.write(struct.pack(">L", 1 + length + padding))
            self.transport.write(struct.pack("B", padding & 0xff))
            self.transport.write(packetObject.buf)
            for i in range(0, padding):
                self.transport.write(struct.pack("B", 0))
        else:
            buf = bytearray()
            buf += struct.pack(">L", 1 + length + padding)
            buf += struct.pack("B", padding & 0xff)
            buf += packetObject.buf
            buf += os.urandom(padding)

            log.info("len(buf)=[{}], padding=[{}].".format(len(buf), padding))

            if self.outHmacSize != 0:
                tmac = hmac.new(self.outHmacKey, digestmod=sha1)
                tmac.update(struct.pack(">L", self.outPacketId))
                tmac.update(buf)

                out = self.outCipher.encrypt(bytes(buf))

                self.transport.write(out)
                self.transport.write(tmac.digest())

        self.outPacketId = (self.outPacketId + 1) & 0xFFFFFFFF

    def process_buffer(self):
        try:
            self._process_buffer()
        except:
            log.exception("_process_buffer() threw:")

    def _process_buffer(self):
        log.info("P: process_buffer(): called (binaryMode={}), buf=[\n{}].".format(self.binaryMode, hex_dump(self.buf)))

        assert self.binaryMode

#        if self.encryption:
#            raise NotImplementedError(errmsg)

        blksize = 16

        if self.inCipher != None:
#            if len(self.buf) > 20: # max(blksize, 20): bs, hmacSize
            if len(self.buf) < blksize:
                return

            offset = 0
            if len(self.cbuf) == 0:
                offset = blksize
                out = self.inCipher.decrypt(self.buf[:offset])
                log.debug("Decrypted [\n{}] to [\n{}].".format(hex_dump(self.buf[:offset]), hex_dump(out)))
                self.cbuf += out
                packet_length = struct.unpack(">L", out[:4])[0]
                log.debug("packet_length=[{}].".format(packet_length))
                if packet_length > 35000:
                    log.warning("Illegal packet_length [{}] received.".format(packet_length))
                    self.transport.close()
                    return
                self.bpLength = packet_length + 4 # Add size of packet_length as we leave it in buf.

            if len(self.buf) < min(1024, self.bpLength - len(self.cbuf) + self.inHmacSize):
                if offset:
                    self.buf = self.buf[offset:]
                return

            l = min(len(self.buf) - self.inHmacSize, self.bpLength) - offset
            bl = (l - l % blksize) + offset
            blks = self.buf[offset:bl]
            self.buf = self.buf[bl:]
            out = self.inCipher.decrypt(blks)
            log.debug("Decrypted [\n{}] to [\n{}].".format(hex_dump(blks), hex_dump(out)))
            self.cbuf += out
            log.debug("len(cbuf)={}, cbuf=[\n{}]".format(len(self.cbuf), hex_dump(self.cbuf)))
        else:
            self.cbuf = self.buf

        while True:
            if self.bpLength is None:
                if len(self.cbuf) < 4:
                    return

                log.info("t=[{}].".format(self.cbuf[:4]))

                packet_length = struct.unpack(">L", self.cbuf[:4])[0]
                log.debug("packet_length=[{}].".format(packet_length))

                if packet_length > 35000:
                    log.warning("Illegal packet_length [{}] received.".format(packet_length))
                    self.transport.close()
                    return

                self.bpLength = packet_length + 4 # Add size of packet_length as we leave it in buf.
            else:
                if len(self.cbuf) < self.bpLength or len(self.buf) < self.inHmacSize:
                    return;

                log.info("PACKET READ (bpLength={}, inHmacSize={}, len(self.cbuf)={}, len(self.buf)={})".format(self.bpLength, self.inHmacSize, len(self.cbuf), len(self.buf)))

                padding_length = struct.unpack("B", self.cbuf[4:5])[0]
                log.debug("padding_length=[{}].".format(padding_length))

                padding_offset = self.bpLength - padding_length

                payload = self.cbuf[5:padding_offset]
                padding = self.cbuf[padding_offset:self.bpLength]
#                mac = self.cbuf[self.bpLength:self.bpLength + self.inHmacSize]
                mac = self.buf[:self.inHmacSize]

                log.debug("payload=[\n{}], padding=[\n{}], mac=[\n{}] len(mac)={}.".format(hex_dump(payload), hex_dump(padding), hex_dump(mac), len(mac)))

                if self.inHmacSize != 0:
                    self.buf = self.buf[self.inHmacSize:]

                    mbuf = struct.pack(">L", self.inPacketId)
                    tmac = hmac.new(self.inHmacKey, digestmod=sha1)
                    tmac.update(mbuf)
                    tmac.update(self.cbuf)
                    cmac = tmac.digest()
                    log.debug("inPacketId={} len(cmac)={}, cmac=[\n{}].".format(self.inPacketId, len(cmac), hex_dump(cmac)))
                    r = hmac.compare_digest(cmac, mac)
                    log.info("HMAC check result: [{}].".format(r))
                    if not r:
                        raise SshException("HMAC check failure, packetId={}.".format(self.inPacketId))

                newbuf = self.cbuf[self.bpLength + self.inHmacSize:]
                if self.cbuf == self.buf:
                    self.cbuf = b''
                    self.buf = newbuf
                else:
                    self.cbuf = newbuf

                if self.waitingForNewKeys:
                    tp = mnetpacket.SshPacket(None, payload)
                    if tp.getPacketType() == mnetpacket.SSH_MSG_NEWKEYS:
                        if self.serverMode:
                            self.init_inbound_encryption()
                        else:
                            """ Disable further processing until inbound encryption is setup.
                                It may not have yet as parameters and newkeys may have come in same tcp packet. """
                            self.set_inbound_enabled(False)
                        self.waitingForNewKeys = False

                self.packet = payload
                self.inPacketId = (self.inPacketId + 1) & 0xFFFFFFFF

                self.bpLength = None

                if self.waiter != None:
                    self.waiter.set_result(False)
                    self.waiter = None

                break;

class SshServerProtocol(SshProtocol):
    def __init__(self, loop):
        super().__init__(loop)

        self.serverMode = True

    def connection_made(self, transport):
        super().connection_made(transport)

        log.info("S: Connection made from [{}].".format(self.address))

        asyncio.async(self._run())

    @asyncio.coroutine
    def _run(self):
        r = yield from connectTaskCommon(self, True)

        if not r:
            return r

        while True:
            packet = yield from self.read_packet()
            m = mnetpacket.SshPacket(None, packet)

            t = m.getPacketType()
            log.debug("Received packet, type=[{}].".format(t))
            if t == mnetpacket.SSH_MSG_CHANNEL_OPEN:
                yield from self.channel_handler.open_channel(self, packet)
            elif t == mnetpacket.SSH_MSG_CHANNEL_DATA:
                yield from self.channel_handler.data(self, packet)

    def data_received(self, data):
        super().data_received(data)

    def error_received(self, exc):
        super().error_received(exc)

    def connection_lost(self, exc):
        super().connection_lost(exc)
        self.client["connected"] = False

class SshClientProtocol(SshProtocol):
    def __init__(self, loop):
        super().__init__(loop)

        self.serverMode = False

    def connection_made(self, transport):
        super().connection_made(transport)
        log.info("C: Connection made to [{}].".format(self.address))
        asyncio.async(clientConnectTask(self))

    def data_received(self, data):
        log.info("C: Received: [{}].".format(data))
        super().data_received(data)

    def error_received(self, exc):
        super().error_received(exc)

    def connection_lost(self, exc):
        super().connection_lost(exc)
        self.client["connected"] = False

class ChannelHandler():
    @asyncio.coroutine
    def open_channel(self, protocol, packet):
        m = mnetpacket.SshChannelOpenMessage(packet)
        log.info("S: Received CHANNEL_OPEN: channel_type=[{}], sender_channel=[{}].".format(m.get_channel_type(), m.get_sender_channel()))

        cm = mnetpacket.SshChannelOpenConfirmationMessage()
        cm.set_recipient_channel(m.get_sender_channel())
        cm.set_sender_channel(0)
        cm.set_initial_window_size(65535)
        cm.set_maximum_packet_size(65535)

        cm.encode()

        protocol.write_packet(cm)

    @asyncio.coroutine
    def data(self, protocol, packet):
        m = mnetpacket.SshChannelDataMessage(packet)
        log.debug("Received data, recipient_channel=[{}], value=[\n{}].".format(m.get_recipient_channel(), hex_dump(m.get_data())))

def main():
    global log, serverKey, clientKey

    print("Starting server.")
    log.info("Starting server.")

    key_filename = "server_key-rsa.mnk"
    if os.path.exists(key_filename):
        log.info("Server private key file found, loading.")
        serverKey = rsakey.RsaKey(filename=key_filename)
    else:
        log.info("Server private key file missing, generating.")
        serverKey = rsakey.RsaKey.generate(bits=4096)
        serverKey.write_private_key_file(key_filename)

    loop = asyncio.get_event_loop()

    chandler = ChannelHandler()

#    f = asyncio.start_server(accept_client, host=None, port=5555)
#    server = loop.create_server(lambda: SshServerProtocol(loop, chandler), "127.0.0.1", 5555)
    host, port = "127.0.0.1", 5555
    server = loop.create_server(lambda: _create_server_protocol(loop), host, port)
    loop.run_until_complete(server)

    log.info("Starting test client.")

    key_filename = "client_key-rsa.mnk"
    if os.path.exists(key_filename):
        log.info("Client private key file found, loading.")
        clientKey = rsakey.RsaKey(filename=key_filename)
    else:
        log.info("Client private key file missing, generating.")
        clientKey = rsakey.RsaKey.generate(bits=4096)
        clientKey.write_private_key_file(key_filename)

    client = loop.create_connection(lambda: _create_client_protocol(loop), "127.0.0.1", 5555)
    loop.run_until_complete(client)

    try:
        loop.run_forever()
    except:
        log.exception("loop.run_forever() threw:")

    client.close()
    server.close()
    loop.close()

def _create_server_protocol(loop):
    ph = SshServerProtocol(loop)
    ph.set_server_key(serverKey)

    p = peer.Peer(TestEngine())
    p.set_protocol_handler(ph)

    return ph

def _create_client_protocol(loop):
    ph = SshClientProtocol(loop)
    ph.set_client_key(clientKey)

    p = peer.Peer(TestEngine())
    p.set_protocol_handler(ph)

    return ph

class TestEngine():
    def connection_made(self, peer):
        pass

    def connection_lost(self, peer, exc):
        pass

if __name__ == "__main__":
    main()
