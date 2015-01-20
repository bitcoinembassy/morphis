import asyncio
import llog
import logging
import struct

clientPipes = {} # task, [reader, writer]
clientObjs = {} # remoteAddress, dict

log = logging.getLogger(__name__)

@asyncio.coroutine
def serverConnectTask(protocol):
    log.info("S: Sending server banner.")
    protocol.transport.write("SSH-2.0-mNet_0.0.1\r\n".encode())

    packet = yield from protocol.read_packet()
    log.info("S: Received packet [{}].".format(packet))

    packet = yield from protocol.read_packet()
    log.info("S: Received packet [{}].".format(packet))

@asyncio.coroutine
def clientConnectTask(protocol):
    log.info("C: Sending client banner.")
    protocol.transport.write("SSH-2.0-mNet_0.0.1\r\n".encode())

    packet = yield from protocol.read_packet()
    log.info("C: Received packet [{}].".format(packet))

    packet = yield from protocol.read_packet()
    log.info("C: Received packet [{}].".format(packet))

class MNetProtocol(asyncio.Protocol):
    def __init__(self, loop):
        self.loop = loop
        self.binaryMode = False
        self.waiter = None
        self.buf = b''
        self.packet = None
        self.bpLength = None
        self.macSize = 0

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
            llog.handle_exception(log, "_data_received()")

    def _data_received(self, data):
        log.debug("data_received(..): start.")

        if self.binaryMode:
            self.buf += data
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

    def process_buffer(self):
        try:
            self._process_buffer()
        except:
            llog.handle_exception(log, "_process_buffer()")



    def _process_buffer(self):
        log.info("P: process_buffer(): called (binaryMode={}, buf=[{}].".format(self.binaryMode, self.buf))

        assert self.binaryMode

#        if self.encryption:
#            raise NotImplementedError(errmsg)

        while True:
            if self.bpLength is None:
                if len(self.buf) < 4:
                    return

                log.info("t=[{}].".format(self.buf[:4]))

                packet_length = struct.unpack(">l", self.buf[:4])[0]
                log.debug("packet_length=[{}].".format(packet_length))

                if packet_length > 35000:
                    log.warning("Illegal packet_length [{}] received.".format(packet_length))
                    self.transport.close()
                    return

                self.bpLength = packet_length + 4 # Add size of packet_length as we leave it in buf.
            else:
                if len(self.buf) < (self.bpLength + self.macSize):
                    return;

                log.info("PACKET READ (bpLength={}, macSize={}, len(self.buf)={})".format(self.bpLength, self.macSize, len(self.buf)))

                padding_length = struct.unpack("B", self.buf[4:5])[0]
                log.debug("padding_length=[{}].".format(padding_length))

                padding_offset = self.bpLength - padding_length

                payload = self.buf[5:padding_offset]
                padding = self.buf[padding_offset:self.bpLength]
                mac = self.buf[self.bpLength:self.bpLength + self.macSize]

                log.debug("payload=[{}], padding=[{}], mac=[{}].".format(payload, padding, mac))

                self.packet = self.buf[0:self.bpLength + self.macSize]
                self.buf = self.buf[self.bpLength + self.macSize:]

                if self.waiter != None:
                    self.waiter.set_result(False)
                    self.waiter = None

                break;

class MNetServerProtocol(MNetProtocol):
    def __init__(self, loop):
        super().__init__(loop)

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

class MNetClientProtocol(MNetProtocol):
    def __init__(self, loop):
        super().__init__(loop)

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
    global log

    print("Starting server.")
    log.info("Starting server.")
    loop = asyncio.get_event_loop()
#    f = asyncio.start_server(accept_client, host=None, port=5555)
    server = loop.create_server(lambda: MNetServerProtocol(loop), "127.0.0.1", 5555)
    loop.run_until_complete(server)

    client = loop.create_connection(lambda: MNetClientProtocol(loop), "127.0.0.1", 5555)
    loop.run_until_complete(client)

#    loop.run_until_complete(f)

    try:
        loop.run_forever()
    except:
        llog.handle_exception(log, "loop.run_forever()")

    client.close()
    server.close()
    loop.close()

if __name__ == "__main__":
    #log.setLevel(logging.DEBUG)
    #formatter = logging.Formatter("%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s")
    #ch = logging.StreamHandler()
    #ch.setLevel(logging.DEBUG)
    #ch.setFormatter(formatter)
    #log.addHandler(ch)

    llog.init()

    main()
