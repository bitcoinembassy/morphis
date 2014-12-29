import asyncio
import time
import zmq

def engageNet(loop, pipe):
    listen_address = "tcp://*:5555"

    context = zmq.Context()
    ssocket = context.socket(zmq.ROUTER)
    ssocket.bind(listen_address)

    print("S: Listening on {}.".format(listen_address))

    csocket = context.socket(zmq.REQ)

    poller = zmq.Poller()
    poller.register(ssocket, zmq.POLLIN)
    poller.register(csocket. zmq.POLLIN)
    poller.register(pipe, zmq.

    i = 0

    while True:
        socks = dict(poller.poll())

        if ssocket in socks:
            # Wait for next request from client.
            address, empty, message = ssocket.recv_multipart()

            print("S: Received request [{}] from [{}].".format(message, address))

            ssocket.send_multipart([address, b'', b"World"])
            print("S: Sent response #{} to [{}]!".format(i, address))
            i = i + 1

        if csocket in socks:
            message = csocket.recv()
            print("C: Received response: [{}].".format(message))
            

def client(loop):
    connect_address = "tcp://localhost:5555"

            csocket.send(b"Hello")
            print("C: Sent request!")


    socket.connect(connect_address)
    print("Connecting to {}.".format(connect_address))

    while True:

def main():
    loop = asyncio.get_event_loop()

    loop.run_in_executor(None, server, loop)
    loop.run_in_executor(None, client, loop)

main()
