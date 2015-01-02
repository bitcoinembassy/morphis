import asyncio
import docopt
import sys
import threading
import time
import traceback
import zmq

from zhelpers import zpipe

import enc

private_key = None;
public_key = None;

in_pipe = None;
out_pipe = None;

def handleException(info, e):
    debug("FATAL: {} threw [{}]: {}".format(info, sys.exc_info()[0], str(e)))
    traceback.print_tb(sys.exc_info()[2])

def debug(message):
    print(message)

def engageNet(loop, context, in_pipe, out_pipe, config):
    try:
        _engageNet(loop, context, in_pipe, out_pipe, config)
    except BaseException as e:
        handleException("_engageNet", e)
        debug("Exiting due to FATAL error.")
        sys.exit(1)

def handleServerRequest():
    global in_pipe, out_pipe

    meta = in_pipe[0].recv_pyobj()
    message = in_pipe[0].recv_multipart()
    in_pipe[0].send(b"ok")

    print("S(a): Received request [{}] from [{}].".format(message, meta["address"]))

    cmd = message.pop(0)

    if cmd == b"pub_key_req":
        remote_pkey = message.pop(0)

        out_pipe[1].send_multipart([b"sresp", meta["address"], b"pub_key_response", public_key.exportKey("PEM")])

def handleClientResponse():
    global in_pipe

    meta = in_pipe[0].recv_pyobj()
    message = in_pipe[0].recv_multipart()

    print("C(a): Received response [{}] from [{}].".format(message, meta["ssockid"]))

def _engageNet(loop, context, in_pipe, out_pipe, config):
    global public_key

    listen_address = "tcp://*:{}".format(config["port"])

    print("S: listen_address=[{}].".format(listen_address))

    ssocket = context.socket(zmq.ROUTER)
    ssocket.identity = b"asdf";
    ssocket.bind(listen_address)

    print("S: Listening on {}.".format(listen_address))

    poller = zmq.Poller()
    poller.register(in_pipe, zmq.POLLIN)
    poller.register(ssocket, zmq.POLLIN)

    i = 0
    clientid = 0

    # fd, id
    csockids = {}
    # id, socket
    csockets = {}

    while True:
        try:
            ready_socks = poller.poll()
        except BaseException as e:
            handleException("poller.poll()", e)
            debug("Exiting due to FATAL error.")
            sys.exit(1)

        print("WOKEN ready_socks=[{}].".format(ready_socks))

        for sockt in ready_socks:
            sock = sockt[0]
            csockid = csockids.get(sock.fd)

            if csockid != None:
                message = sock.recv_multipart()

                print("C: Received response [{}] from [{}].".format(message, csockid))

                meta = {"type": "clientResponse",
                    "csockid": csockid}

                in_pipe.send_pyobj(meta, zmq.SNDMORE)
                in_pipe.send_multipart(message)

                loop.call_soon_threadsafe(handleClientResponse)

#                sock.send(b"Hello")
#                print("C: Sent request to [{}]!".format(csockid))
            elif sock == ssocket:
                # Wait for next request from client.
                address = ssocket.recv();
                empty = ssocket.recv();
                
                message = ssocket.recv_multipart()

                print("S: Received request [{}] from [{}].".format(message, address))

                meta = {"type": "serverRequest",
                    "address": address}

                out_pipe.send_pyobj(meta, zmq.SNDMORE)
                out_pipe.send_multipart(message)

                loop.call_soon_threadsafe(handleServerRequest)

#                ssocket.send_multipart([address, b'', b"World"])
#                print("S: Sent response #{} to [{}]!".format(i, address))
#                i = i + 1
            elif sock == in_pipe:
                message = in_pipe.recv_multipart()
                print("XS: Received [{}] message.".format(message[0]))

                in_pipe.send(b"ok")

                cmd = message.pop(0)
                if cmd == b"conn":
                    addr = message.pop(0)
                    #addr = message[1];
                    print("C: Connecting to [{}].".format(addr))

                    csocket = context.socket(zmq.REQ)
                    csocket.connect(addr)

                    csockids[csocket.fd] = clientid
                    csockets[clientid] = csocket
                    clientid += 1
                    poller.register(csocket, zmq.POLLIN)

                    csocket.send(b"pub_key_req", zmq.SNDMORE)
                    csocket.send(public_key.exportKey("PEM"))
                    print("C: Sent request!")
                elif cmd == b"sresp":
                    addr = message.pop(0)

                    print("S: Sending response [{}] to [{}].".format(message, addr))

                    ssocket.send(addr, zmq.SNDMORE)
                    ssocket.send(b"", zmq.SNDMORE)
                    ssocket.send_multipart(message)
                elif cmd == b"shutdown":
                    return

def main():
    global in_pipe, out_pipe, public_key, private_key

    try:
        docopt_config = "Usage: my_program.py [--port=PORT] [--connect=PORT]"
        arguments = docopt.docopt(docopt_config)
        port = arguments["--port"]
        if port == None:
            port = 5555

        connect_dest = arguments["--connect"]
    except docopt.DocoptExit as e:
        print(e.message)
        return

    context = zmq.Context()

    in_pipe = zpipe(context)
    out_pipe = zpipe(context)

    loop = asyncio.get_event_loop()

    net_config = {"port": port}

    # Generate Node Keys & Id.
    private_key = enc.generate_RSA(4096)
    public_key = private_key.publickey();
    
#    debug("Private Key=[%s], Public Key=[%s]." % (str(private_key.exportKey("PEM")),  str(public_key.exportKey("PEM"))))

    node_id = enc.generate_ID(public_key.exportKey("DER"))

    debug("node_id=[%s]." % node_id.hexdigest())

    # Start Net Engine.
    zmq_future = loop.run_in_executor(None, engageNet, loop, context, out_pipe[0], in_pipe[1], net_config)
#    thread = threading.Thread(target=engageNet, args=(loop, context, out_pipe[0], in_pipe[1], net_config))
#    thread.daemon = True
#    thread.start()

    # Connect for testing.
    if connect_dest != None:
        out_pipe[1].send_multipart([b"conn", "tcp://{}".format(connect_dest).encode()])
#    out_pipe[0].send_multipart([b"conn", "tcp://localhost:{}".format(port).encode()])

    try:
        loop.run_until_complete(zmq_future)
    except BaseException as e:
        handleException("loop.run_until_complete()", e)
        out_pipe[1].send_multipart([b"shutdown"])
        loop.stop()
        loop.close()
        zmq_future.cancel()
        sys.exit(1)

main()
