import llog

import asyncio
import cmd
import logging
import queue as tqueue

from mutil import hex_dump
import sshtype

log = logging.getLogger(__name__)

class Shell(object):
    def __init__(self, peer, local_cid, queue):
        self.peer = peer
        self.local_cid = local_cid
        self.queue = queue

        self.mshell = None

    def run(self):
        cmd_queue = tqueue.Queue()

        loop = self.peer.engine.node.loop
        protocol = self.peer.protocol
        local_cid = self.local_cid

        class Io(object):
            def readline(self):
                return cmd_queue.get()

            def writeln(self, val):
                self.write(val + "\n")

            def write(self, val):
                loop.call_soon_threadsafe(self._write, val)

            def _write(self, val):
                val = val.replace('\n', "\r\n")
                rmsg = StringMessage()
                rmsg.value = val
                protocol.write_channel_data(local_cid, rmsg.encode())

            def flush(self):
                pass

        self.mshell = MShell(Io())
        task = loop.run_in_executor(None, self.mshell.run)
        asyncio.async(task, loop=loop)

        buf = bytearray()

        while True:
            packet = yield from self.queue.get()
            msg = StringMessage(packet)

            log.debug("value=\n[{}].".format(hex_dump(msg.value.encode())))

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
                        local_cid, rmsg.encode())

                    buf = buf[:-1]
                    continue

            buf += msg.value.encode()

            rmsg = StringMessage()
            rmsg.value = msg.value.replace('\n', "\r\n")
            self.peer.protocol.write_channel_data(local_cid, rmsg.encode())

            i = buf.find(b'\r')
            if i == -1:
                continue

            buf[i] = ord(b'\n')
            i += 1
            line = buf[:i].decode()
            buf = buf[i:]

            cmd_queue.put(line)
        
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

class MShell(cmd.Cmd):
    intro = "Hello, test. Type help or ? to list commands."
    prompt = "(morphis) "
    use_rawinput = False

    def __init__(self, io):
        super().__init__(stdin=io, stdout=io)

    def run(self):
        log.info("RUNNNNNNNNNNN")

        try:
            self.cmdloop()
        except:
            log.exception("cmdloop() threw exception:")

        log.info("EXITING")

    def do_test(self, arg):
        'Test thing'
        self.stdout.writeln("Hello, I received your test.")

    def do_quit(self, arg):

    def emptyline(self):
        pass
