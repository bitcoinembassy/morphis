import llog

import asyncio
from enum import Enum
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
from sshexception import SshException
from mutil import hex_dump
import peer

MAX_PACKET_LENGTH = 35000

log = logging.getLogger(__name__)

server_key = None
client_key = None

cleartext_transport_enabled = False

def enable_cleartext_transport():
    global cleartext_transport_enabled
    cleartext_transport_enabled = True

class Status(Enum):
    new = 0
    ready = 10
    closed = 20
    disconnected = 30

class SshProtocol(asyncio.Protocol):
    def __init__(self, loop):
        self.loop = loop

        self.address = None

        self.transport = None

        self._next_channel_id = 0
        self.channel_queues = {}

        self.channel_handler = None
        self.connection_handler = None

        self.server_mode = None

        self.binaryMode = False
        self.inboundEnabled = True

        self.status = Status.new

        self.server_key = server_key
        self.client_key = client_key
        self.k = None
        self.h = None
        self.session_id = None
        self.inCipher = None
        self.outCipher = None
        self.inHmacKey = None
        self.outHmacKey = None
        self.inHmacSize = 0
        self.outHmacSize = 0
        self.waitingForNewKeys = False

        self.waiter = None
        self.ready_waiter = None
        self.buf = bytearray()
        self.cbuf = self.buf
        self.packet = None
        self.bpLength = None

        self.inPacketId = 0
        self.outPacketId = 0

        self.remote_banner = None
        self.local_kex_init_message = None
        self.remote_kex_init_message = None

        self._channel_map = {} # {local_cid, remote_cid}
        self._reverse_channel_map = {} # {remote_cid, local_cid}

    def set_connection_handler(self, value):
        self.connection_handler = value

    def set_channel_handler(self, value):
        self.channel_handler = value

    def get_transport(self):
        return self.transport

    def close(self):
        if self.transport:
            self.transport.close()
        self.status = Status.closed

    @asyncio.coroutine
    def open_channel(self, channel_type, block=False):
        "Returns the channel queue for the new channel."

        if self.status is Status.new:
            if not block:
                raise SshException("Connection is not ready yet.")

            assert not self.ready_waiter
            self.ready_waiter = asyncio.futures.Future(loop=self.loop)

            try:
                yield from self.ready_waiter
            finally:
                self.waiter = None
        elif self.status is not Status.ready:
            # Ignore if it is closed or disconnected.
            if log.isEnabledFor(logging.INFO):
                log.info("open_channel(..) called on a closed connection.")
            return None, None

        local_cid = self._open_channel(channel_type)

        queue = self._create_channel_queue()
        self.channel_queues[local_cid] = queue

        if block:
            r = yield from queue.get()
            if not r:
                # Could be None for disconnect or False for rejected.
                return local_cid, r
            assert r == True, "r=[{}]!".format(r)

        return local_cid, queue

    def _open_channel(self, channel_type):
        local_cid = self._allocate_channel_id()

        if log.isEnabledFor(logging.INFO):
            log.info("Opening channel [{}] (address=[{}])."\
                .format(local_cid, self.address))

        msg = mnetpacket.SshChannelOpenMessage()
        msg.channel_type = channel_type
        msg.sender_channel = local_cid
        msg.initial_window_size = 65535
        msg.maximum_packet_size = 65535
        msg.encode()

        self.write_packet(msg)

        self._channel_map[local_cid] = -1

        return local_cid

    @asyncio.coroutine
    def close_channel(self, local_cid):
        if log.isEnabledFor(logging.INFO):
            log.info("Closing channel {} (address=[{}])."\
                .format(local_cid, self.address))

        if self.status is not Status.ready:
            # Ignore this call if we are closed or disconnected.
            assert self.status is not Status.new
            return False

        remote_cid = self._channel_map.get(local_cid)
        if remote_cid is None:
            if log.isEnabledFor(logging.INFO):
                log.info("close_channel(..) called on unmapped channel [{}]."\
                    .format(local_cid))
            return False
        if remote_cid == -1 or remote_cid == -2:
            if log.isEnabledFor(logging.INFO):
                log.info("close_channel(..) called on channel in state [{}]."\
                    .format(remote_cid))
            return False

        msg = mnetpacket.SshChannelCloseMessage()
        msg.recipient_channel = remote_cid
        msg.encode()

        self.write_packet(msg)

        self._channel_map[local_cid] = -2
        yield from self.channel_queues.pop(local_cid).put(None)

    def _create_channel_queue(self):
        return asyncio.Queue()

    def _allocate_channel_id(self):
        nid = self._next_channel_id
        self._next_channel_id += 1
        return nid

    @asyncio.coroutine
    def verify_server_key(self, key_data, sig):
        key = rsakey.RsaKey(key_data)

        if not key.verify_ssh_sig(self.h, sig):
            raise SshException("Signature verification failed.")

        log.info("Signature validated correctly!")

        if self.server_key:
            if self.server_key.asbytes() != key_data:
                raise SshException("Key provided by server differs from that which we were expecting.")

        self.server_key = key

        r = yield from self.connection_handler.peer_authenticated(self)

        return r

    def set_K_H(self, k, h):
        self.k = k
        self.h = h

        if self.session_id == None:
            self.session_id = h

    def set_inbound_enabled(self, val):
        self.inboundEnabled = val

    @property
    def local_banner(self):
        if cleartext_transport_enabled:
            return "SSH-2.0-mNet_0.0.1+cleartext"
        else:
            return "SSH-2.0-mNet_0.0.1"

    def init_outbound_encryption(self):
        log.info("Initializing outbound encryption.")
        # use: AES.MODE_CBC: bs: 16, ks: 32. hmac-sha1=20 key size.
        if not self.server_mode:
            iiv = self.generateKey(b'A', 16)
            ekey = self.generateKey(b'C', 32)
            ikey = self.generateKey(b'E', 20)
        else:
            iiv = self.generateKey(b'B', 16)
            ekey = self.generateKey(b'D', 32)
            ikey = self.generateKey(b'F', 20)

        if log.isEnabledFor(logging.DEBUG):
            log.debug("ekey=[{}], iiv=[{}].".format(ekey, iiv))

        self.outCipher = AES.new(ekey, AES.MODE_CBC, iiv)
        self.outHmacKey = ikey
        self.outHmacSize = 20

    def init_inbound_encryption(self):
        log.info("Initializing inbound encryption.")
        # use: AES.MODE_CBC: bs: 16, ks: 32. hmac-sha1=20 key size.
        if not self.server_mode:
            iiv = self.generateKey(b'B', 16)
            ekey = self.generateKey(b'D', 32)
            ikey = self.generateKey(b'F', 20)
        else:
            iiv = self.generateKey(b'A', 16)
            ekey = self.generateKey(b'C', 32)
            ikey = self.generateKey(b'E', 20)

        if log.isEnabledFor(logging.DEBUG):
            log.debug("ekey=[{}], iiv=[{}].".format(ekey, iiv))

        self.inCipher = AES.new(ekey, AES.MODE_CBC, iiv)
        self.inHmacKey = ikey
        self.inHmacSize = 20

    def generateKey(self, extra, needed_bytes):
        assert isinstance(extra, bytes) and len(extra) == 1

        buf = bytearray()
        buf += sshtype.encodeMpint(self.k)
        buf += self.h
        buf += extra
        buf += self.session_id

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

        log.info("P: Connection made with [{}].".format(peer_name))

        self.connection_handler.connection_made(self)

        asyncio.async(self._process_ssh_protocol(), loop=self.loop)

    @asyncio.coroutine
    def _process_ssh_protocol(self):
        yield from connectTaskCommon(self, self.server_mode)

        if cleartext_transport_enabled\
                and self.remote_banner.endswith("+cleartext"):
            r = yield from connectTaskInsecure(self, self.server_mode)
        else:
            r = yield from connectTaskSecure(self, self.server_mode)

        if not r:
            return r

        # Connected and fully authenticated at this point.
        self.status = Status.ready
        if self.ready_waiter != None:
            self.ready_waiter.set_result(False)
            self.ready_waiter = None
        yield from self.connection_handler.connection_ready()

        while True:
            packet = yield from self.read_packet(False)
            if not packet:
                return

            m = mnetpacket.SshPacket(None, packet)

            t = m.packet_type
            log.info("Received packet, type=[{}].".format(t))
            if t == mnetpacket.SSH_MSG_CHANNEL_OPEN:
                msg = mnetpacket.SshChannelOpenMessage(packet)
                log.info("P: Received CHANNEL_OPEN: channel_type=[{}], sender_channel=[{}].".format(msg.channel_type, msg.sender_channel))

                if self._reverse_channel_map.get(msg.sender_channel):
                    log.warning("Remote end sent a CHANNEL_OPEN request with an already open remote id; ignoring.")
                    continue

                r = yield from\
                    self.channel_handler.request_open_channel(self, msg)

                if r:
                    local_cid = self._accept_channel_open(msg)

                    if log.isEnabledFor(logging.INFO):
                        log.info("Channel [{}] opened (address=[{}])."\
                            .format(local_cid, self.address))

                    queue = self._create_channel_queue()
                    self.channel_queues[local_cid] = queue

                    yield from self.channel_handler.channel_opened(\
                        self, msg.channel_type, local_cid, queue)
                else:
                    self._open_channel_reject(msg)

            elif t == mnetpacket.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                msg = mnetpacket.SshChannelOpenConfirmationMessage(packet)
                log.info("P: Received CHANNEL_OPEN_CONFIRMATION:"\
                    " sender_channel=[{}], recipient_channel=[{}]."\
                    .format(msg.sender_channel, msg.recipient_channel))

                rcid = self._channel_map.get(msg.recipient_channel)
                if rcid == None:
                    log.warning("Received a CHANNEL_OPEN_CONFIRMATION for a local channel that was not started; ignoring.")
                    return
                if rcid == -2:
                    log.warning("Received a CHANNEL_OPEN_CONFIRMATION for a local channel that was closed; ignoring.")
                    return
                if rcid != -1:
                    log.warning("Received a CHANNEL_OPEN_CONFIRMATION for a local channel that was already open; ignoring.")
                    return

                lcid = self._reverse_channel_map\
                    .setdefault(msg.sender_channel, msg.recipient_channel)

                if lcid is not msg.recipient_channel:
                    log.warning("Received a CHANNEL_OPEN_CONFIRMATION for a remote channel that is already open; ignoring.")
                    return

                self._channel_map[msg.recipient_channel] = msg.sender_channel

                if log.isEnabledFor(logging.INFO):
                    log.info("Channel [{}] opened (address=[{}])."\
                        .format(msg.recipient_channel, self.address))

                # First 'packet' is a True, signaling the channel is open to
                # those yielding from the queue.
                queue = self.channel_queues[msg.recipient_channel]
                yield from queue.put(True)

                yield from self.channel_handler\
                    .channel_opened(self, None, msg.recipient_channel, queue)

            elif t == mnetpacket.SSH_MSG_CHANNEL_OPEN_FAILURE:
                msg = mnetpacket.SshChannelOpenFailureMessage(packet)
                log.info("P: Received CHANNEL_OPEN_FAILURE recipient_channel=[{}].".format(msg.recipient_channel))

                queue = self.channel_queues[msg.recipient_channel]
                yield from queue.put(False)
                yield from self._close_channel(msg.recipient_channel)
                yield from self.channel_handler.channel_open_failed(self, msg)

            elif t == mnetpacket.SSH_MSG_CHANNEL_DATA:
                msg = mnetpacket.SshChannelDataMessage(packet)
                log.info("P: Received CHANNEL_DATA recipient_channel=[{}].".format(msg.recipient_channel))

                r = yield from self.channel_handler.channel_data(self, packet)
                if not r:
                    log.info(\
                        "Adding protocol (address={}) channel [{}] data"\
                        " to queue."\
                        .format(self.address, msg.recipient_channel))
                    yield from self.channel_queues[msg.recipient_channel]\
                        .put(msg.data)
            elif t == mnetpacket.SSH_MSG_CHANNEL_CLOSE:
                msg = mnetpacket.SshChannelCloseMessage(packet)
                log.info("P: Received CHANNEL_CLOSE recipient_channel=[{}]"\
                    .format(msg.recipient_channel))

                yield from self._close_channel(msg.recipient_channel)
                yield from self.channel_handler.channel_closed(self, msg.recipient_channel)
            elif t == mnetpacket.SSH_MSG_CHANNEL_REQUEST:
                msg = mnetpacket.SshChannelRequest(packet)
                if log.isEnabledFor(logging.INFO):
                    log.info("Received SSH_MSG_CHANNEL_REQUEST:"\
                    " recipient_channel=[{}], request_type=[{}],"\
                    " want_reply=[{}]."\
                        .format(msg.recipient_channel, msg.request_type,\
                            msg.want_reply))
                yield from self.channel_handler.channel_request(self, msg)
            else:
                log.warning("Unhandled packet of type [{}].".format(t))

    def _accept_channel_open(self, req_msg):
        log.info("Accepting channel open request.")

        local_cid = self._allocate_channel_id()

        self._channel_map[local_cid] = req_msg.sender_channel
        self._reverse_channel_map[req_msg.sender_channel] = local_cid

        cm = mnetpacket.SshChannelOpenConfirmationMessage()
        cm.recipient_channel = req_msg.sender_channel
        cm.sender_channel = local_cid
        cm.initial_window_size = 65535
        cm.maximum_packet_size = 65535

        cm.encode()

        self.write_packet(cm)

        return local_cid

    def _open_channel_reject(self, req_msg):
        log.info("Rejecting channel open request.")

        fm = mnetpacket.SshChannelOpenFailureMessage()
        fm.recipient_channel = req_msg.sender_channel
        fm.reason_code = 0
        fm.description = "invalid"
        fm.language_tag = "en"

        fm.encode()

        self.write_packet(fm)

    @asyncio.coroutine
    def _close_channel(self, local_cid):
        remote_cid = self._channel_map.pop(local_cid)

        if remote_cid != -1 and remote_cid != -2:
            assert remote_cid >= 0, "remote_cid=[{}].".format(remote_cid)
            msg = mnetpacket.SshChannelCloseMessage()
            msg.recipient_channel = remote_cid
            msg.encode()
            self.write_packet(msg)

        queue = self.channel_queues.pop(local_cid, None)
        if queue:
            yield from queue.put(None)

        if log.isEnabledFor(logging.INFO):
            log.info("Channel [{}] closed (address=[{}])."\
                .format(local_cid, self.address))

    def data_received(self, data):
        try:
            self._data_received(data)
        except:
            log.exception("_data_received() threw:")

    def error_received(self, exc):
        log.info("X: Error received: {}".format(exc))
        self.connection_handler.error_received(self, exc)

    def connection_lost(self, exc):
        log.info("X: Connection lost to [{}].".format(self.address))

        self.status = Status.closed

        self._channel_map.clear()

        self._close_queues()

        self.connection_handler.connection_lost(self, exc)

    def _close_queues(self):
        for queue in self.channel_queues.values():
            #yield from queue.put(None)
            queue.put_nowait(None)

    def _data_received(self, data):
        if log.isEnabledFor(logging.DEBUG):
            log.debug("data_received(..): start.")
            log.debug("X: Received: [\n{}].".format(hex_dump(data)))

        if self.binaryMode:
            self.buf += data
            if not self.packet and self.inboundEnabled:
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
    def read_packet(self, require_connected=True):
        if self.status is Status.disconnected:
            return None

        if require_connected and self.status is Status.closed:
            errstr = "ProtocolHandler closed, refusing read_packet(..)!"
            log.debug(errstr)
            raise SshException(errstr)

        if self.packet != None:
            packet = self.packet
            self.packet = None

            if packet[0] == 0x01:
                yield from\
                    self._peer_disconnected(\
                        mnetpacket.SshDisconnectMessage(packet))
                return None

            log.info("P: Returning next packet.")

            #asyncio.call_soon(self.process_buffer())
            # For now, call process_buffer in this event.
            if len(self.buf) > 0:
                self.process_buffer()

            return packet

        if self.status is Status.closed:
            return None

        log.info("P: Waiting for packet.")
        yield from self.do_wait()

        assert self.packet != None
        packet = self.packet
        self.packet = None

        log.info("P: Notified of packet.")

        if packet[0] == 0x01:
            yield from\
                self._peer_disconnected(\
                    mnetpacket.SshDisconnectMessage(packet))
            return None

        # For now, call process_buffer in this event.
        if len(self.buf) > 0:
            self.process_buffer()

        return packet

    def _peer_disconnected(self, msg):
        if log.isEnabledFor(logging.INFO):
            log.info("Remote end (address=[{}]) send Disconnect message"\
                " (reason_code={}, description=[{}])."\
                    .format(self.address, msg.reason_code, msg.description))

        self.status = Status.disconnected

        yield from self.connection_handler.peer_disconnected(self, msg)

    def write_packet(self, packet):
        if log.isEnabledFor(logging.INFO):
            log.info("Writing packet_type=[{}] ({} bytes) to address=[{}]."\
                .format(packet.packet_type, len(packet.buf), self.address))
            if log.isEnabledFor(logging.DEBUG):
                log.debug("data=[\n{}].".format(hex_dump(packet.buf)))

        self.write_data([packet.buf])

    def write_channel_data(self, local_cid, data):
        log.info("Writing to channel {} with {} bytes of data (address={}).".format(local_cid, len(data), self.address))

        remote_cid = self._channel_map.get(local_cid)
        if remote_cid == None:
            return False

        msg = mnetpacket.SshChannelDataMessage()
        msg.recipient_channel = remote_cid
        msg.encode()

        self.write_data((msg.buf, data))
        return True

    def write_data(self, datas):
        if self.status in [Status.closed, Status.disconnected]:
            log.info("ProtocolHandler closed, ignoring write_data(..) call.")
            return

        mod_size = None
        if self.outCipher == None:
            mod_size = 8 # RFC says 8 minimum.
        else:
            mod_size = 16 # bs of current cipher is 16.

        length = 0
        for data in datas:
            length += len(data)

        if log.isEnabledFor(logging.INFO):
            log.info("Writing {} bytes of data to connection (address=[{}])."\
                .format(length, self.address))

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
            for data in datas:
                self.transport.write(data)
            for i in range(0, padding):
                self.transport.write(struct.pack("B", 0))
        else:
            buf = bytearray()
            buf += struct.pack(">L", 1 + length + padding)
            buf += struct.pack("B", padding & 0xff)
            for data in datas:
                buf += data
            buf += os.urandom(padding)

            if log.isEnabledFor(logging.DEBUG):
                log.debug("len(buf)=[{}], padding=[{}].".format(len(buf), padding))

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
        if log.isEnabledFor(logging.DEBUG):
            log.debug("P: process_buffer(): called (binaryMode={}), buf=[\n{}].".format(self.binaryMode, hex_dump(self.buf)))

        assert self.binaryMode

        self._process_encrypted_buffer()

        # cbuf is clear text buf.
        while True:
            if self.bpLength is None:
                assert not self.inCipher

                if len(self.cbuf) < 4:
                    return

                if log.isEnabledFor(logging.DEBUG):
                    log.debug("t=[{}].".format(self.cbuf[:4]))

                packet_length = struct.unpack(">L", self.cbuf[:4])[0]

                if log.isEnabledFor(logging.DEBUG):
                    log.debug("packet_length=[{}].".format(packet_length))

                if packet_length > MAX_PACKET_LENGTH:
                    log.warning("Illegal packet_length [{}] received.".format(packet_length))
                    self.close()
                    return

                self.bpLength = packet_length + 4 # Add size of packet_length as we leave it in buf.
            else:
                if len(self.cbuf) < self.bpLength or len(self.buf) < self.inHmacSize:
                    return;

                if log.isEnabledFor(logging.DEBUG):
                    log.debug("PACKET READ (bpLength={}, inHmacSize={}, len(self.cbuf)={}, len(self.buf)={})".format(self.bpLength, self.inHmacSize, len(self.cbuf), len(self.buf)))

                padding_length = struct.unpack("B", self.cbuf[4:5])[0]
                log.debug("padding_length=[{}].".format(padding_length))

                padding_offset = self.bpLength - padding_length

                payload = self.cbuf[5:padding_offset]
                padding = self.cbuf[padding_offset:self.bpLength]
#                mac = self.cbuf[self.bpLength:self.bpLength + self.inHmacSize]
                mac = self.buf[:self.inHmacSize]

                if log.isEnabledFor(logging.DEBUG):
                    log.debug("payload=[\n{}], padding=[\n{}], mac=[\n{}] len(mac)={}.".format(hex_dump(payload), hex_dump(padding), hex_dump(mac), len(mac)))

                if self.inHmacSize != 0:
                    self.buf = self.buf[self.inHmacSize:]

                    mbuf = struct.pack(">L", self.inPacketId)
                    tmac = hmac.new(self.inHmacKey, digestmod=sha1)
                    tmac.update(mbuf)
                    tmac.update(self.cbuf)
                    cmac = tmac.digest()
                    if log.isEnabledFor(logging.DEBUG):
                        log.debug("inPacketId={} len(cmac)={}, cmac=[\n{}].".format(self.inPacketId, len(cmac), hex_dump(cmac)))
                    r = hmac.compare_digest(cmac, mac)
                    log.info("HMAC check result: [{}].".format(r))
                    if not r:
                        raise SshException("HMAC check failure, packetId={}.".format(self.inPacketId))

                newbuf = self.cbuf[self.bpLength + self.inHmacSize:]
                if self.cbuf == self.buf:
                    self.cbuf = bytearray()
                    self.buf = newbuf
                else:
                    self.cbuf = newbuf

                if self.waitingForNewKeys:
                    tp = mnetpacket.SshPacket(None, payload)
                    if tp.packet_type == mnetpacket.SSH_MSG_NEWKEYS:
                        if self.server_mode:
                            self.init_inbound_encryption()
                        else:
                            # Disable further processing until inbound
                            # encryption is setup. It may not have yet as
                            # parameters and newkeys may have come in same tcp
                            # packet.
                            self.set_inbound_enabled(False)
                        self.waitingForNewKeys = False

                self.packet = payload
                self.inPacketId = (self.inPacketId + 1) & 0xFFFFFFFF

                self.bpLength = None

                if self.waiter != None:
                    self.waiter.set_result(False)
                    self.waiter = None

                break;

    def _process_encrypted_buffer(self):
        blksize = 16

        if self.inCipher != None:
#            if len(self.buf) > 20: # max(blksize, 20): bs, hmacSize
            if len(self.buf) < blksize:
                return

            offset = 0
            if len(self.cbuf) == 0:
                offset = blksize
                out = self.inCipher.decrypt(self.buf[:offset])
                if log.isEnabledFor(logging.DEBUG):
                    log.debug("Decrypted [\n{}] to [\n{}].".format(hex_dump(self.buf[:offset]), hex_dump(out)))
                self.cbuf += out
                packet_length = struct.unpack(">L", out[:4])[0]
                log.debug("packet_length=[{}].".format(packet_length))
                if packet_length > MAX_PACKET_LENGTH:
                    errmsg = "Illegal packet_length [{}] received.".format(packet_length)
                    log.warning(errmsg)
                    self.close()
                    raise SshException(errmsg)
                self.bpLength = packet_length + 4 # Add size of packet_length as we leave it in buf.
                if self.bpLength == blksize:
                    self.buf = self.buf[offset:]
                    return

            if len(self.buf) - offset < min(1024, self.bpLength - len(self.cbuf) + self.inHmacSize):
                if offset:
                    self.buf = self.buf[offset:]
                return

            l = min(len(self.buf), self.bpLength - len(self.cbuf))
            if not l:
                return

            bl = (l - l % blksize) + offset
            blks = self.buf[offset:bl]
            self.buf = self.buf[bl:]
            out = self.inCipher.decrypt(blks)
            self.cbuf += out

            if log.isEnabledFor(logging.DEBUG):
                log.debug("Decrypted [\n{}] to [\n{}].".format(hex_dump(blks), hex_dump(out)))
                log.debug("len(cbuf)={}, cbuf=[\n{}]".format(len(self.cbuf), hex_dump(self.cbuf)))
        else:
            self.cbuf = self.buf

class SshServerProtocol(SshProtocol):
    def __init__(self, loop):
        super().__init__(loop)

        self.server_mode = True

    def connection_made(self, transport):
        super().connection_made(transport)

    def data_received(self, data):
        super().data_received(data)

    def error_received(self, exc):
        super().error_received(exc)

    def connection_lost(self, exc):
        super().connection_lost(exc)

class SshClientProtocol(SshProtocol):
    def __init__(self, loop):
        super().__init__(loop)

        self.server_mode = False

    def connection_made(self, transport):
        super().connection_made(transport)

    def data_received(self, data):
        super().data_received(data)

    def error_received(self, exc):
        super().error_received(exc)

    def connection_lost(self, exc):
        super().connection_lost(exc)

# Returns True on success, False on failure.
@asyncio.coroutine
def connectTaskCommon(protocol, server_mode):
    assert isinstance(server_mode, bool)

    log.info("X: Sending banner.")
    protocol.transport.write((protocol.local_banner + "\r\n").encode(encoding="UTF-8"))

    # Read banner.
    packet = yield from protocol.read_packet()
    log.info("X: Received banner [{}].".format(packet))

    protocol.remote_banner = packet.decode(encoding="UTF-8")

# Returns True on success, False on failure.
@asyncio.coroutine
def connectTaskInsecure(protocol, server_mode):
    m = mnetpacket.SshKexdhReplyMessage()
    if server_mode:
        m.host_key = protocol.server_key.asbytes()
    else:
        m.host_key = protocol.client_key.asbytes()
    m.f = 42
    m.signature = b"test"
    m.encode()

    protocol.write_packet(m)

    pkt = yield from protocol.read_packet()
    m = mnetpacket.SshKexdhReplyMessage(pkt)

    if server_mode:
        if protocol.client_key:
            if protocol.client_key.asbytes() != m.host_key:
                raise SshException("Key provided by client differs from that which we were expecting.")
        protocol.client_key = rsakey.RsaKey(m.host_key)
    else:
        if protocol.server_key:
            if protocol.server_key.asbytes() != m.host_key:
                raise SshException("Key provided by server differs from that which we were expecting.")
        protocol.server_key = rsakey.RsaKey(m.host_key)

    r = yield from protocol.connection_handler.peer_authenticated(protocol)
    if not r:
        # Peer is rejected for some reason by higher level.
        protocol.close()
        return False

    return True

# Returns True on success, False on failure.
@asyncio.coroutine
def connectTaskSecure(protocol, server_mode):
    # Send KexInit packet.
    opobj = mnetpacket.SshKexInitMessage()
    opobj.cookie = os.urandom(16)
#    opobj.kex_algorithms = "diffie-hellman-group-exchange-sha256"
    opobj.kex_algorithms = "diffie-hellman-group14-sha1"
    opobj.server_host_key_algorithms = "ssh-rsa"
    opobj.encryption_algorithms_client_to_server = "aes256-cbc"
    opobj.encryption_algorithms_server_to_client = "aes256-cbc"
#    opobj.mac_algorithms_client_to_server = "hmac-sha2-512"
#    opobj.mac_algorithms_server_to_client = "hmac-sha2-512"
    opobj.mac_algorithms_client_to_server = "hmac-sha1"
    opobj.mac_algorithms_server_to_client = "hmac-sha1"
    opobj.compression_algorithms_client_to_server = "none"
    opobj.compression_algorithms_server_to_client = "none"
    opobj.encode()

    protocol.local_kex_init_message = opobj.buf

    protocol.write_packet(opobj)

    # Read KexInit packet.
    packet = yield from protocol.read_packet()
    if log.isEnabledFor(logging.DEBUG):
        log.debug("X: Received packet [{}].".format(hex_dump(packet)))

    pobj = mnetpacket.SshPacket(None, packet)
    packet_type = pobj.packet_type
    log.info("packet_type=[{}].".format(packet_type))

    if packet_type != 20:
        log.warning("Peer sent unexpected packet_type[{}], disconnecting.".format(packet_type))
        protocol.close()
        return False

    protocol.remote_kex_init_message = packet

    pobj = mnetpacket.SshKexInitMessage(packet)
    if log.isEnabledFor(logging.DEBUG):
        log.debug("cookie=[{}].".format(pobj.cookie))
    log.info("keyExchangeAlgorithms=[{}].".format(pobj.kex_algorithms))

    protocol.waitingForNewKeys = True

    ke = kex.KexGroup14(protocol)
    log.info("Calling start_kex()...")
    r = yield from ke.do_kex()

    if not r:
        # Client is rejected for some reason by higher level.
        protocol.close()
        return False

    # Setup encryption now that keys are exchanged.
    protocol.init_outbound_encryption()

    if not protocol.server_mode:
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

    if protocol.server_mode:
        packet = yield from protocol.read_packet()
#        m = mnetpacket.SshPacket(None, packet)
#        log.info("X: Received packet (type={}) [{}].".format(m.packet_type, packet))
        m = mnetpacket.SshServiceRequestMessage(packet)
        log.info("Service requested [{}].".format(m.service_name))

        if m.service_name != "ssh-userauth":
            raise SshException("Remote end requested unexpected service (name=[{}]).".format(m.service_name))

        mr = mnetpacket.SshServiceAcceptMessage()
        mr.service_name = "ssh-userauth"
        mr.encode()

        protocol.write_packet(mr)

        packet = yield from protocol.read_packet()
        m = mnetpacket.SshUserauthRequestMessage(packet)
        log.info("Userauth requested with method=[{}].".format(m.method_name))

        if m.method_name == "none":
            mr = mnetpacket.SshUserauthFailureMessage()
            mr.auths = "publickey"
            mr.partial_success = False
            mr.encode()

            protocol.write_packet(mr)

            packet = yield from protocol.read_packet()
            m = mnetpacket.SshUserauthRequestMessage(packet)
            log.info("Userauth requested with method=[{}].".format(m.method_name))

        if m.method_name != "publickey":
            raise SshException("Unhandled client auth method [{}].".format(m.method_name))
        if m.algorithm_name != "ssh-rsa":
            raise SshException("Unhandled client auth algorithm [{}].".format(m.algorithm_name))

        log.debug("m.signature_present()={}.".format(m.signature_present))

        if not m.signature_present:
            mr = mnetpacket.SshUserauthPkOkMessage()
            mr.algorithm_name = m.algorithm_name
            mr.public_key = m.public_key
            mr.encode()

            protocol.write_packet(mr)

            packet = yield from protocol.read_packet()
            m = mnetpacket.SshUserauthRequestMessage(packet)
            log.info("Userauth requested with method=[{}].".format(m.method_name))

            if m.method_name != "publickey":
                raise SshException("Unhandled client auth method [{}].".format(m.method_name))
            if m.algorithm_name != "ssh-rsa":
                raise SshException("Unhandled client auth algorithm [{}].".format(m.algorithm_name))

        if log.isEnabledFor(logging.DEBUG):
            log.debug("signature=[{}].".format(hex_dump(m.signature)))

        signature = m.signature

        buf = bytearray()
        buf += sshtype.encodeBinary(protocol.session_id)
        buf += packet[:-m.signature_length]

        client_key = rsakey.RsaKey(m.public_key)
        r = client_key.verify_ssh_sig(buf, signature)

        log.info("Userauth signature check result: [{}].".format(r))
        if not r:
            raise SshException("Signature and key provided by client did not match.")

        if protocol.client_key:
            if protocol.client_key.asbytes() != m.public_key:
                raise SshException("Key provided by client differs from that which we were expecting.")

        protocol.client_key = client_key

        r = yield from protocol.connection_handler.peer_authenticated(protocol)
        if not r:
            # Client is rejected for some reason by higher level.
            protocol.close()
            return False

        mr = mnetpacket.SshUserauthSuccessMessage()
        mr.encode()

        protocol.write_packet(mr)
    else:
        # client mode.
        m = mnetpacket.SshServiceRequestMessage()
        m.service_name = "ssh-userauth"
        m.encode()

        protocol.write_packet(m)

        packet = yield from protocol.read_packet()
        m = mnetpacket.SshServiceAcceptMessage(packet)
        log.info("Service request accepted [{}].".format(m.service_name))

        mr = mnetpacket.SshUserauthRequestMessage()
        mr.user_name = "dev"
        mr.service_name = "ssh-connection"
        mr.method_name = "publickey"
        mr.signature_present = True
        mr.algorithm_name = "ssh-rsa"

        ckey = protocol.client_key
        mr.public_key = ckey.asbytes()

        mr.encode()

        mrb = bytearray()
        mrb += sshtype.encodeBinary(protocol.session_id)
        mrb += mr.buf

        sig = sshtype.encodeBinary(ckey.sign_ssh_data(mrb))

        mrb = mr.buf
        assert mr.buf == mrb
        mrb += sig

        protocol.write_packet(mr)

        packet = yield from protocol.read_packet()
        m = mnetpacket.SshUserauthSuccessMessage(packet)
        log.info("Userauth accepted.")

    log.info("Connect task done (server={}).".format(server_mode))

#    if not server_mode:
#        protocol.close()

    return True

class ChannelHandler():
    @asyncio.coroutine
    def channel_opened(self, protocol, channel_type, local_cid):
        pass

    @asyncio.coroutine
    def channel_data(self, protocol, packet):
        m = mnetpacket.SshChannelDataMessage(packet)
        if log.isEnabledFor(logging.DEBUG):
            log.debug("Received data, recipient_channel=[{}], value=[\n{}].".format(m.recipient_channel, hex_dump(m.data)))

def main():
    global log, server_key, client_key

    print("Starting server.")
    log.info("Starting server.")

    key_filename = "server_key-rsa.mnk"
    if os.path.exists(key_filename):
        log.info("Server private key file found, loading.")
        server_key = rsakey.RsaKey(filename=key_filename)
    else:
        log.info("Server private key file missing, generating.")
        server_key = rsakey.RsaKey.generate(bits=4096)
        server_key.write_private_key_file(key_filename)

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
        client_key = rsakey.RsaKey(filename=key_filename)
    else:
        log.info("Client private key file missing, generating.")
        client_key = rsakey.RsaKey.generate(bits=4096)
        client_key.write_private_key_file(key_filename)

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
    ph.server_key = server_key

    p = peer.Peer(TestEngine())
    p.protocol = ph

    return ph

def _create_client_protocol(loop):
    ph = SshClientProtocol(loop)
    ph.client_key = client_key

    p = peer.Peer(TestEngine())
    p.protocol = ph

    return ph

class TestEngine():
    def connection_made(self, peer):
        pass

    def connection_lost(self, peer, exc):
        pass

if __name__ == "__main__":
    main()
