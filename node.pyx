import asyncio
import docopt
import sys
import threading
import time
import traceback
import zmq

from zhelpers import zpipe

import enc

def debug(message):
    print(message)

def engageNet(loop, context, pipe, config):
    try:
        _engageNet(loop, context, pipe, config)
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        debug("FATAL: _engageNet threw [{}]: {}".format(exc_type, str(e)))
#        fname = exc_tb.tb_frame.f_code.co_filename
#        print(exc_type, fname, exc_tb.tb_lineno)
        traceback.print_tb(exc_tb)
        debug("Exiting due to FATAL error.")
        sys.exit(1)

def _engageNet(loop, context, pipe, config):
    listen_address = "tcp://*:{}".format(config["port"])

    print("S: listen_address=[{}].".format(listen_address))

    ssocket = context.socket(zmq.ROUTER)
    ssocket.identity = b"asdf";
    ssocket.bind(listen_address)

    print("S: Listening on {}.".format(listen_address))

    poller = zmq.Poller()
    poller.register(pipe, zmq.POLLIN)
    poller.register(ssocket, zmq.POLLIN)

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

                sock.send(b"Hello")
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
    try:
        docopt_config = "Usage: my_program.py [--port=PORT]"
        arguments = docopt.docopt(docopt_config)
        port = arguments["--port"]
        if port == None:
            port = 5555
    except docopt.DocoptExit as e:
        print(e.message)
        return

    context = zmq.Context()

    pipe = zpipe(context)

    loop = asyncio.get_event_loop()

    net_config = {"port": port}

    #loop.run_in_executor(None, engageNet, loop, context, pipe[0])
    thread = threading.Thread(target=engageNet, args=(loop, context, pipe[1], net_config))
#    thread.daemon = True
    thread.start()

#    pipe[0].send_multipart([b"conn", "tcp://localhost:{}".format(port).encode()])

    private_key = enc.generate_RSA(4096)
    public_key = private_key.publickey();
    
#    debug("Private Key=[%s], Public Key=[%s]." % (str(private_key.exportKey("PEM")),  str(public_key.exportKey("PEM"))))

    node_id = enc.generate_ID(public_key.exportKey("DER"))

    debug("node_id=[%s]." % node_id.hexdigest())

main()
