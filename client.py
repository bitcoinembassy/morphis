import llog

import asyncio
import logging
import os

import chord_tasks
import mbase32
import mn1
import packet as mnp
import rsakey
from shell import BinaryMessage

log = logging.getLogger(__name__)

class Client(object):
    def __init__(self, loop, client_key=None, address="127.0.0.1:4250"):
        self.loop = loop
        self.address = address

        self.cid = None
        self.queue = None

        if client_key is None:
            client_key = rsakey.RsaKey.generate(bits=4096)
        self.client_key = client_key
        self.server_key = None

        self._ready = asyncio.Event(loop=loop)

    @asyncio.coroutine
    def connect(self):
        if log.isEnabledFor(logging.INFO):
            log.info("Connecting to addr=[{}].".format(self.address))

        host, port = self.address.split(':')

        client = self.loop.create_connection(
            self._create_client_protocol, host, port)

        try:
            transport, protocol = yield from client
        except Exception as ex:
            if log.isEnabledFor(logging.INFO):
                log.info("Connection failed: {}: {}".format(type(ex), ex))

            return False

        if log.isEnabledFor(logging.INFO):
            log.info("Connected!")

        yield from self._ready.wait()

        cid, queue = yield from\
            protocol.open_channel("session", True)

        if not queue:
            return False

        self.cid = cid
        self.queue = queue

        return True

    def _create_client_protocol(self):
        ph = mn1.SshClientProtocol(self.loop)
        ph.client_key = self.client_key
        if self.server_key:
            ph.server_key = self.server_key

        ph.connection_handler = ConnectionHandler(self)
        ph.channel_handler = ChannelHandler(self)

        self.protocol = ph

        return ph

    @asyncio.coroutine
    def disconnect(self):
        yield from self.protocol.close_channel(self.cid)
        self.protocol.close()

    @asyncio.coroutine
    def send_command(self, command, args=None):
        if log.isEnabledFor(logging.INFO):
            log.info("Sending command [{}] with args [{}]."\
                .format(command, args))

        msg = BinaryMessage()
        msg.value = command.encode() + b"\r\n"

        self.protocol.send_channel_request(\
            self.cid, "exec", False, msg.encode())

        data = yield from self.queue.get()

        if not data:
            return False

        msg = BinaryMessage(data)

        return msg.value

    @asyncio.coroutine
    def _send_request(self, msg):
        self.protocol.write_channel_data(self.cid, msg.encode())

        log.info("Sent request.")

        return (yield from self.queue.get())

    @asyncio.coroutine
    def send_store_data(self, data, key_callback):
        data_enc = base58.encode(data)

        r = yield from self.send_command("storeblockenc {}".format(data_enc))

        p1 = r.find(b']')
        data_key = mbase32.decode(r[10:p1].decode("UTF-8"))

        key_callback(data_key)

    @asyncio.coroutine
    def send_get_data(self, data_key, path=None):
        data_key_enc = mbase32.encode(data_key)

        if path:
            cmd = "getdata {} {}".format(data_key_enc, path)
        else:
            cmd = "getdata {}".format(data_key_enc)

        r = yield from self.send_command(cmd)

        data_rw = chord_tasks.DataResponseWrapper(data_key)

        p0 = r.find(b"version=[") + 9
        p1 = r.find(b']', p0)
        data_rw.version = r[p0:p1]
        p0 = p1 + 1

        p0 = r.find(b"data:\r\n", p0) + 7
        data_rw.data = r[p0:]

        return data_rw

class ConnectionHandler(mn1.ConnectionHandler):
    def __init__(self, client):
        self.client = client

    @asyncio.coroutine
    def connection_ready(self, protocol):
        self.client._ready.set()

    @asyncio.coroutine
    def peer_authenticated(self, protocol):
        return True

class ChannelHandler(mn1.ChannelHandler):
    def __init__(self, client):
        self.client = client
