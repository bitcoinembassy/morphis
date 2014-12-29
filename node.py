import threading
import asyncio
import time
import zmq

from zhelpers import zpipe

def engageNet(loop, context, pipe):
    listen_address = "tcp://*:5555"

    ssocket = context.socket(zmq.ROUTER)
    ssocket.identity = b"asdf";
    ssocket.bind(listen_address)

    print("S: Listening on {}.".format(listen_address))

    csocket = context.socket(zmq.ROUTER)

    poller = zmq.Poller()
    poller.register(pipe, zmq.POLLIN)
    poller.register(ssocket, zmq.POLLIN)
#    poller.register(csocket, zmq.POLLIN)

    i = 0
    clientid = 0

    csocks = {}

    while True:
        try:
            ready_socks = poller.poll()
        except:
            break

        print("WOKEN")

        for sockt in ready_socks:
            sock = sockt[0]
            csockid = csocks.get(sock.fd)

            if csockid != None:
                message = sock.recv()

                print("C: Received response [{}] from [{}].".format(message, csockid))

                csocket.send(b"Hello")
                print("C: Sent request to [{}]!".format(csockid))
            elif sock == ssocket:
                # Wait for next request from client.
                address, empty, message = ssocket.recv_multipart()

                print("S: Received request [{}] from [{}].".format(message, address))

                ssocket.send_multipart([address, b'', b"World"])
                print("S: Sent response #{} to [{}]!".format(i, address))
                i = i + 1
            elif sock == pipe:
                message = pipe.recv_multipart()
                print("XS: Received [{}] message.".format(message[0]))

                cmd = message.pop(0)
                if cmd == b"conn":
                    addr = message.pop(0)
                    #addr = message[1];
                    print("C: Connecting to [{}].".format(addr))

                    csocket = context.socket(zmq.REQ)
                    csocket.connect(addr)

                    csocks[csocket.fd] = clientid
                    clientid += 1
                    poller.register(csocket, zmq.POLLIN)

                    csocket.send(b"Hello")
                    print("C: Sent request!")

def main():
    context = zmq.Context()

    pipe = zpipe(context)

    loop = asyncio.get_event_loop()

    #loop.run_in_executor(None, engageNet, loop, context, pipe[0])
    thread = threading.Thread(target=engageNet, args=(loop, context, pipe[1]))
#    thread.daemon = True
    thread.start()

    pipe[0].send_multipart([b"conn", b"tcp://localhost:5555"])

main()
