import asyncio
import llog
import logging

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
        self.packet = None
        self.buf = b''

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

            if len(self.buf) > 0:
                self.process_buffer()
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
            return packet

        log.info("P: Waiting for packet.")
        yield from self.do_wait()

        assert self.packet != None
        packet = self.packet
        self.packet = None

        log.info("P: Returning packet.")

        return packet

    def process_buffer(self):
        log.info("P: process_buffer(): called (binaryMode={}, buf=[{}].".format(self.binaryMode, self.buf))

        assert self.binaryMode

        errmsg = "TODO: YOU_ARE_HERE"
        log.fatal(errmsg)
        raise NotImplementedError(errmsg)
        #TODO: YOU_ARE_HERE


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
