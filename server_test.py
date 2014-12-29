import time
import zmq

listen_address = "tcp://*:5555"

context = zmq.Context()
ssocket = context.socket(zmq.ROUTER)
ssocket.bind(listen_address)

print("Listening on %s." % listen_address)

while True:
    # Wait for next request from client.
    address, empty, message = ssocket.recv_multipart()

#    message = ssocket.recv()

    print("Received request: %s" % message)

    # simulate work
    time.sleep(1);

    ssocket.send_multipart([address, b'', b"World"])
    print("Sent response!")

