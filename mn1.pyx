import asyncio
import llog
import logging

clientPipes = {} # task, [reader, writer]
clientObjs = {} # remoteAddress, dict

log = logging.getLogger(__name__)

class MNetServerProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport
        self.peerName = peer_name = transport.get_extra_info("peername")

        log.info("S: Connection made from [{}].".format(peer_name))

        client = clientObjs.get(peer_name)
        if client == None:
            log.info("S: Initializing new clientObj.")
            client = {"connected": True}
        clientObjs[peer_name] = client

        self.client = client

        transport.write("SSH-2.0-mNet_0.0.1\n".encode())

    def data_received(self, data):
        log.info("S: Received: [{}].".format(data.rstrip().decode()))

        log.info("S: Closing socket.")
        self.transport.close()

    def error_recieved(self, exc):
        log.info("S: Error received:".format(exc))

    def connection_lost(self, exc):
        log.info("S: Connection lost from [{}], client=[{}].".format(self.peerName, self.client))
        self.client["connected"] = False

class MNetClientProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport
        self.peerName = peer_name = transport.get_extra_info("peername")

        log.info("C: Connection made from [{}].".format(peer_name))

    def data_received(self, data):
        log.info("C: Received: [{}].".format(data.rstrip().decode()))

        log.info("C: Closing socket.")
        self.transport.close()

    def error_recieved(self, exc):
        log.info("C: Error received:".format(exc))

    def connection_lost(self, exc):
        log.info("C: Connection lost from [{}], client=[{}].".format(self.peerName, self.client))
        self.client["connected"] = False

def main():
    global log

    print("Starting server.")
    log.info("Starting server.")
    loop = asyncio.get_event_loop()
#    f = asyncio.start_server(accept_client, host=None, port=5555)
    server = loop.create_server(MNetServerProtocol, "127.0.0.1", 5555)
    loop.run_until_complete(server)

    client = loop.create_connection(MNetClientProtocol, "127.0.0.1", 5555)
    loop.run_until_complete(client)

#    loop.run_until_complete(f)
    loop.run_forever()
    client.close()
    server.close()
    loop.run_until_complete(client.wait_closed())
    loop.run_until_complete(server.wait_closed())
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
