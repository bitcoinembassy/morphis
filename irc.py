# Höfundarréttur (c) eilífur  Heimur-Heilinn
# License: GPL v2.

import llog

import asyncio
from enum import Enum
import logging

log = logging.getLogger(__name__)

class Status(Enum):
    new = 0
    ready = 10
    closed = 20
    disconnected = 30

class IrcProtocol(asyncio.Protocol):
    def __init__(self, loop):
        self.loop = loop

        self.address = None # (host, port)

        self.transport = None

        self.server_mode = None

        self.status = Status.new

        self.connection_handler = None

        self._packet = None
        self._waiter = None

        self._buf = bytearray()
        self._buf_last_check_idx = 0

    def close(self):
        if self.transport:
            self.transport.close()
        self.status = Status.closed

    def is_closed(self):
        return self.status is Status.closed

    def connection_made(self, transport):
        self.transport = transport
        self.address = peername = transport.get_extra_info("peername")

        if log.isEnabledFor(logging.INFO):
            log.info("Connection made with [{}].".format(peername))

        if self.connection_handler:
            self.connection_handler.connection_made(self)

        asyncio.async(self._process_irc_protocol(), loop=self.loop)

    @asyncio.coroutine
    def read_packet(self):
        if self.status is Status.disconnected:
            return None

#        if require_connected and self.status is Status.closed:
        if self.status is Status.closed:
            errstr = "ProtocolHandler closed, refusing read_packet(..)!"
            if log.isEnabledFor(logging.DEBUG):
                log.debug(errstr)
            raise SshException(errstr)

        packet = self._packet
        if packet != None:
            self._packet = None

            if log.isEnabledFor(logging.DEBUG):
                log.debug("Returning next packet.")

            if len(self._buf) > 0:
                self._process_buffer()

            return packet

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Waiting for packet.")

        yield from self._do_wait_packet()

        if self.status is Status.closed or self.status is Status.disconnected:
            return None

        packet = self._packet
        assert packet != None
        self._packet = None

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Notified of packet.")

        if len(self._buf) > 0:
            self._process_buffer()

        return packet

    @asyncio.coroutine
    def _process_irc_protocol(self):
        try:
            r = yield from connectTaskServer(self)

            if not r:
                return r
        except Exception as e:
            log.exception("Exception performing connect task.")
            raise

        self.status = Status.ready

        if self.connection_handler:
            yield from self.connection_handler.connection_ready(self)

        while True:
            packet = yield from self.read_packet()
            if not packet:
                return

            yield from self._process_irc_packet(packet)

    @asyncio.coroutine
    def _process_irc_packet(self, packet):
        if log.isEnabledFor(logging.DEBUG):
            log.info("Received packet: [{}].".format(packet))

        #TODO: YOU_ARE_HERE:

    def data_received(self, data):
        try:
            self._data_received(data)
        except Exception:
            log.exception("_data_received() threw:")

    def error_received(self, exc):
        if log.isEnabledFor(logging.INFO):
            log.info("Error received: {}".format(exc))
        if self.connection_handler:
            self.connection_handler.error_received(self, exc)

    def connection_lost(self, exc):
        if log.isEnabledFor(logging.INFO):
            log.info("Connection lost to [{}].".format(self.address))

        self.status = Status.closed

        if self._waiter != None:
            self._waiter.set_result(False)
            self._waiter = None

        if self.connection_handler:
            self.connection_handler.connection_lost(self, exc)

    @asyncio.coroutine
    def _do_wait_packet(self):
        if self._waiter is not None:
            errmsg = "Waiter already set!"
            log.fatal(errmsg)
            raise Exception(errmsg)

        self._waiter = asyncio.futures.Future(loop=self.loop)

        try:
            yield from self._waiter
        finally:
            self._waiter = None

    def _data_received(self, data):
        if log.isEnabledFor(logging.DEBUG):
            log.debug("_data_received(..): start.")
            log.debug("Received: [{}].".format(data))

        self._buf += data

        self._process_buffer()

    def _process_buffer(self):
        p1 = self._buf.find(b"\r\n", self._buf_last_check_idx)

        if p1 == -1:
            self._buf_last_check_idx = len(self._buf)
            return

        self._packet = self._buf[:p1]

        self._buf = self._buf[p1:]

        if self._waiter != None:
            self._waiter.set_result(False)
            self._waiter = None

# Returns True on success, False on failure.
@asyncio.coroutine
def connectTaskServer(protocol):
    log.info("doing task...")

    protocol.transport.write(b"HI\r\n")

    return True

#TODO: Clean up, copy-pasted from mn1.py.
class ConnectionHandler(object):
    def connection_made(self, protocol):
        pass

    def error_recieved(self, protocol, exc):
        pass

    def connection_lost(self, protocol, exc):
        pass

    @asyncio.coroutine
    def peer_disconnected(self, protocol, msg):
        pass

    @asyncio.coroutine
    def peer_authenticated(self, protocol):
        pass

    @asyncio.coroutine
    def connection_ready(self, protocol):
        pass

@asyncio.coroutine
def _main(loop):
    log.info("Launching MORPHiS Test IRCd.")

    addr = "127.0.0.1:6667"
    host, port = addr.split(':')

    def create_server_protocol():
        return IrcProtocol(loop)

    server = loop.create_server(create_server_protocol, host, port)

    yield from server

    log.info("Listening on [{}:{}].".format(host, port))

def main():
    loop = asyncio.get_event_loop()

    asyncio.async(_main(loop), loop=loop)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        log.warning("Got KeyboardInterrupt; shutting down.")
    except Exception:
        log.exception("loop.run_forever() threw:")

    loop.close()

    log.info("Shutdown.")

if __name__ == "__main__":
    main()
