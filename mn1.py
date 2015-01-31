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
import dsskey as pdss
import rsakey as prsa
import sshtype
from sshexception import *

clientPipes = {} # task, [reader, writer]
clientObjs = {} # remoteAddress, dict

log = logging.getLogger(__name__)

serverKey = None

# Returns True on success, False on failure.
@asyncio.coroutine
def connectTaskCommon(protocol, serverMode):
    try:
        yield from _connectTaskCommon(protocol, serverMode)
    except:
        log.exception("_connectTaskCommon() threw:")

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

    log.debug("outgoing packet=[{}].".format(opobj.getBuf()))
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

    packet = yield from protocol.read_packet()
    m = mnetpacket.SshPacket(None, packet)
    log.info("X: Received packet (type={}) [{}].".format(m.getPacketType(), packet))

    if protocol.serverMode:
        m = mnetpacket.SshServiceRequestMessage(packet)
        log.info("Service requested [{}].".format(m.get_service_name()))

    log.debug("Connect task done (server={}).".format(serverMode))

    return True

@asyncio.coroutine
def serverConnectTask(protocol):
    r = yield from connectTaskCommon(protocol, True)
    if not r:
        return r


@asyncio.coroutine
def clientConnectTask(protocol):
    r = yield from connectTaskCommon(protocol, False)
    if not r:
        return r

class SshProtocol(asyncio.Protocol):
    def __init__(self, loop):
        self.loop = loop

        self.serverMode = None

        self.binaryMode = False
        self.inboundEnabled = True

        self.serverKey = serverKey
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
        self.OutPacketId = 0

        self.remoteBanner = None
        self.localKexInitMessage = None
        self.remoteKexInitMessage = None

    def get_server_key(self):
        return self.serverKey

    def verify_server_key(self, key_data, sig):
        key = prsa.RsaKey(key_data)

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
        self.peerName = peer_name = transport.get_extra_info("peername")

        log.debug("P: Connection made with [{}].".format(peer_name))

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

    def _data_received(self, data):
        log.debug("data_received(..): start.")

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

        log.debug("Writing [{}] bytes of data.".format(length))

        extra = (length + 5) % 8;
        if extra != 0:
            padding = 8 - extra
            if padding < 4:
                padding += 8 #Minimum is 4, we need mod 8.
        else:
            padding = 8; #Minimum is 4, we need mod 8.

        self.transport.write(struct.pack(">L", 1 + length + padding))
        self.transport.write(struct.pack("B", padding & 0xff))

        self.transport.write(packetObject.buf)
        self.transport.write(os.urandom(padding))

        if self.outHmacSize != 0:
            raise NotImplementedError("TODO")

    def process_buffer(self):
        try:
            self._process_buffer()
        except:
            log.exception("_process_buffer() threw:")

    def _process_buffer(self):
        log.info("P: process_buffer(): called (binaryMode={}, buf=[{}].".format(self.binaryMode, self.buf))

        assert self.binaryMode

#        if self.encryption:
#            raise NotImplementedError(errmsg)

        if self.inCipher != None:
            if len(self.buf) > 20: # max(16, 20): bs, hmacSize
                try:
                    l = len(self.buf) - 20 # Reserve hmac.
                    bl = l - l % 16
                    blks = self.buf[:bl]
                    self.buf = self.buf[bl:]
                    out = self.inCipher.decrypt(blks)
                    log.debug("Decrypted [{}] to [{}].".format(blks, out))
                    self.cbuf += out
                    log.debug("cbuf=[{}], len={}".format(self.cbuf, len(self.cbuf)))
                except:
                    log.exception("inCiper.decrypt(..)")
            else:
                return
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

                log.debug("payload=[{}], padding=[{}], mac=[{}] len(mac)={}.".format(payload, padding, mac, len(mac)))

                if self.inHmacSize != 0:
                    self.buf = self.buf[self.inHmacSize:]

                    mbuf = struct.pack(">L", self.inPacketId)
                    tmac = hmac.new(self.inHmacKey, digestmod=sha1)
                    tmac.update(mbuf)
                    tmac.update(self.cbuf)
                    cmac = tmac.digest()
                    log.debug("inPacketId={} cmac=[{}], len={}.".format(self.inPacketId, cmac, len(cmac)))
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
        log.info("S: Connection made from [{}].".format(self.peerName))
        asyncio.async(serverConnectTask(self))

    def data_received(self, data):
        log.info("S: Received: [{}].".format(data))
        super().data_received(data)

    def error_recieved(self, exc):
        log.info("S: Error received: {}".format(exc))

    def connection_lost(self, exc):
        log.info("S: Connection lost from [{}], client=[{}].".format(self.peerName, self.client))
        self.client["connected"] = False

class SshClientProtocol(SshProtocol):
    def __init__(self, loop):
        super().__init__(loop)

        self.serverMode = False

    def connection_made(self, transport):
        super().connection_made(transport)
        log.info("C: Connection made to [{}].".format(self.peerName))
        asyncio.async(clientConnectTask(self))

    def data_received(self, data):
        log.info("C: Received: [{}].".format(data))
        super().data_received(data)

    def error_recieved(self, exc):
        log.info("C: Error received: {}".format(exc))

    def connection_lost(self, exc):
        log.info("C: Connection lost to [{}], client=[{}].".format(self.peerName, self.client))
        self.client["connected"] = False

def main():
    global log, serverKey

    print("Starting server.")
    log.info("Starting server.")

    key_filename = "server_key-rsa.mnk"
    if os.path.exists(key_filename):
        log.info("Server private key file found, loading.")
        serverKey = prsa.RsaKey(filename=key_filename)
    else:
        log.info("Server private key file missing, generating.")
        serverKey = prsa.RsaKey.generate(bits=4096)
        serverKey.write_private_key_file(key_filename)

    loop = asyncio.get_event_loop()

#    f = asyncio.start_server(accept_client, host=None, port=5555)
    server = loop.create_server(lambda: SshServerProtocol(loop), "127.0.0.1", 5555)
    loop.run_until_complete(server)

    client = loop.create_connection(lambda: SshClientProtocol(loop), "127.0.0.1", 5555)
    loop.run_until_complete(client)

#    loop.run_until_complete(f)

    try:
        loop.run_forever()
    except:
        log.exception("loop.run_forever() threw:")

    client.close()
    server.close()
    loop.close()

if __name__ == "__main__":
    main()
