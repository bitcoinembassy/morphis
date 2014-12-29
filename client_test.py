import time
import zmq

connect_address = "tcp://localhost:5555"

context = zmq.Context()
socket = context.socket(zmq.REQ)
socket.connect(connect_address)

print("Connecting to %s." % connect_address)

while True:
    socket.send(b"Hello")
    print("Sent request!")

    message = socket.recv()
    print("Received response: %s" % message)

    # simulate work
#    time.sleep(1);


