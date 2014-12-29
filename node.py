import asyncio
import time
import zmq

def server(loop):
    listen_address = "tcp://*:5555"

    context = zmq.Context()
    ssocket = context.socket(zmq.ROUTER)
    ssocket.bind(listen_address)

    print("S: Listening on {}.".format(listen_address))

    i = 0

    while True:
        # Wait for next request from client.
        address, empty, message = ssocket.recv_multipart()

    #    message = ssocket.recv()

        print("S: Received request [{}] from [{}].".format(message, address))

        # simulate work
#        time.sleep(1);

        ssocket.send_multipart([address, b'', b"World"])
        print("S: Sent response #{} to [{}]!".format(i, address))
        i = i + 1

def client(loop):
    connect_address = "tcp://localhost:5555"

    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.connect(connect_address)

    print("Connecting to {}.".format(connect_address))

    while True:
        socket.send(b"Hello")
        print("C: Sent request!")

        message = socket.recv()
        print("C: Received response: [{}].".format(message))

        # simulate work
#        time.sleep(1);

def main():
    loop = asyncio.get_event_loop()

    loop.run_in_executor(None, server, loop)
    loop.run_in_executor(None, client, loop)

main()
