import llog

import asyncio
import cmd
import logging
import queue as tqueue

from mutil import hex_dump
import sshtype

log = logging.getLogger(__name__)

class Shell(cmd.Cmd):
    intro = "Hello, test. Type help or ? to list commands."
    prompt = "(morphis) "
    use_rawinput = False

    def __init__(self, peer, local_cid, queue):
        super().__init__(stdin=None, stdout=self)

        self.peer = peer
        self.local_cid = local_cid
        self.queue = queue

    @asyncio.coroutine
    def cmdloop(self):
        self.preloop()
        
        if self.intro:
            self.stdout.write(str(self.intro) + '\n')

        assert not self.cmdqueue
        assert not self.use_rawinput

        stop = None
        while not stop:
            self.stdout.write(self.prompt)
            self.stdout.flush()

            line = yield from self.readline()

            if line == None:
                line = "EOF"

            self.writeln("")

            log.info("Processing command line: [{}].".format(line))

            line = self.precmd(line)
            stop = self.onecmd(line)
            stop = self.postcmd(stop, line)

        self.postloop()

    @asyncio.coroutine
    def readline(self):
        buf = bytearray()

        while True:
            packet = yield from self.queue.get()
            if not packet:
                return None

            msg = StringMessage(packet)

            if log.isEnabledFor(logging.DEBUG):
                log.debug("Received text:\n[{}].".format(hex_dump(msg.value.encode())))
            else:
                log.info("Received text [{}].".format(msg.value))

            if len(msg.value) == 1:
                char = ord(msg.value[0])
                if char == 0x7f:
                    rbuf = bytearray(7)
                    rbuf[0] = 0x1b
                    rbuf[1] = 0x5b
                    rbuf[2] = 0x44
                    rbuf[3] = ord(' ')
                    rbuf[4] = 0x1b
                    rbuf[5] = 0x5b
                    rbuf[6] = 0x44

                    rmsg = StringMessage()
                    rmsg.value = rbuf.decode()

                    self.peer.protocol.write_channel_data(\
                        self.local_cid, rmsg.encode())

                    buf = buf[:-1]
                    continue

            buf += msg.value.encode()

            rmsg = StringMessage()
            rmsg.value = msg.value.replace('\n', "\r\n")
            self.peer.protocol.write_channel_data(self.local_cid, rmsg.encode())

            i = buf.find(b'\r')
            if i == -1:
                continue

            line = buf[:i].decode()
            buf = buf[i+1:]

            return line

    def writeln(self, val):
        self.write(val + "\n")

    def write(self, val):
        val = val.replace('\n', "\r\n")
        rmsg = StringMessage()
        rmsg.value = val
        self.peer.protocol.write_channel_data(self.local_cid, rmsg.encode())

    def flush(self):
        pass

    def do_test(self, arg):
        'Test thing'
        self.stdout.writeln("Hello, I received your test.")

    def do_quit(self, arg):
        self.peer.protocol.transport.close()
        return True

    def emptyline(self):
        pass

class StringMessage():
    def __init__(self, buf = None):
        self.buf = buf

        self.value = None

        if buf:
            self.parse()

    def encode(self):
        nbuf = bytearray()

        nbuf += sshtype.encodeString(self.value)

        return nbuf

    def parse(self):
        i = 1
        l, self.value = sshtype.parseString(self.buf)
