import asyncio
import llog
import logging

logger = None
clients = {} # task, [reader, writer]

def log():
    global logger
    if logger == None:
        logger = logging.getLogger(__name__)
    return logger

def accept_client(client_reader, client_writer):
    global log

    task = asyncio.Task(handle_client(client_reader, client_writer))
    clients[task] = (client_reader, client_writer)

    def client_done(task):
        del clients[task]
        client_writer.close()
        log().info("End connection.")

    log().info("New connection.")
    task.add_done_callback(client_done)

@asyncio.coroutine
def handle_client(client_reader, client_writer):
    client_writer.write("SSH-2.0-mNet_0.0.1\n".encode())

    try:
        data = yield from asyncio.wait_for(client_reader.readline(), timeout=2.0)
    except asyncio.TimeoutError:
        log().warning("Client sent no line data by timeout.")
        assert data == None
        return

    sdata = data.decode().rstrip()
    log().info("Received [{}].".format(sdata))

def main():
    global log

    print("Starting server.")
    log().info("Starting server.")
    loop = asyncio.get_event_loop()
    f = asyncio.start_server(accept_client, host=None, port=5555)
    loop.run_until_complete(f)
    loop.run_forever()

if __name__ == "__main__":
    #log.setLevel(logging.DEBUG)
    #formatter = logging.Formatter("%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s")
    #ch = logging.StreamHandler()
    #ch.setLevel(logging.DEBUG)
    #ch.setFormatter(formatter)
    #log.addHandler(ch)

    llog.init()

    main()
