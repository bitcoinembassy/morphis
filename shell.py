import llog

import asyncio
import cmd
import logging
import queue as tqueue

import chord
import db
import enc
import mn1
from mutil import hex_dump, hex_string
import sshtype

log = logging.getLogger(__name__)

UP_ARROW = bytearray([0x1b, 0x5b, 0x41])
DOWN_ARROW = bytearray([0x1b, 0x5b, 0x42])
RIGHT_ARROW = bytearray([0x1b, 0x5b, 0x43])
LEFT_ARROW = bytearray([0x1b, 0x5b, 0x44])

class Shell(cmd.Cmd):
    intro = "Welcome to the Morphis Shell Socket."\
        " Type help or ? to list commands."
    prompt = "(morphis) "
    use_rawinput = False

    def __init__(self, loop, peer, local_cid, queue):
        super().__init__(stdin=None, stdout=self)

        self.loop = loop
        self.peer = peer
        self.local_cid = local_cid
        self.queue = queue

        self.out_buffer = bytearray()

        self.shell_locals = {}
        self.shell_locals["self"] = self

    @asyncio.coroutine
    def cmdloop(self):
        self.preloop()
        
        if self.intro:
            self.write(str(self.intro) + '\n')

        assert not self.cmdqueue
        assert not self.use_rawinput

        exit = stop = None
        while not stop:
            self.write(self.prompt)
            self.flush()

            line = yield from self.readline()

            if line == None:
                line = "EOF"
                exit = True

            self.writeln("")

            line = self.precmd(line)
            stop = yield from self.onecmd(line)
            stop = self.postcmd(stop, line)

            if exit:
                break

        self.postloop()

    @asyncio.coroutine
    def onecmd(self, line):
        log.info("Processing command line: [{}].".format(line))

        cmd, arg, line = self.parseline(line)

        if not line:
            return self.emptyline()
        if cmd is None:
            return self.default(line)
        if line == "EOF":
            self.lastcmd = ""
        else:
            self.lastcmd = line

        if cmd == "":
            return self.default(line)

        try:
            func = getattr(self, "do_" + cmd)
        except AttributeError:
            return self.default(line)

        if asyncio.iscoroutinefunction(func):
            r = yield from func(arg)
            return r
        else:
            return func(arg)

    @asyncio.coroutine
    def readline(self):
        buf = bytearray()
        savedcmd = None

        while True:
            packet = yield from self.queue.get()
            if not packet:
                log.info("Shell shutting down.")
                return None

            msg = BinaryMessage(packet)

            if log.isEnabledFor(logging.DEBUG+1):
                if log.isEnabledFor(logging.DEBUG):
                    log.debug("Received text:\n[{}]."\
                        .format(hex_dump(msg.value)))
                else:
                    log.log(logging.DEBUG+1, "Received text [{}]."\
                        .format(msg.value))

            lenval = len(msg.value)
            if lenval == 1:
                char = msg.value[0]
                if char == 0x7f:
                    if not buf:
                        continue

                    self.write(LEFT_ARROW)
                    self.write(b' ')
                    self.write(LEFT_ARROW)
                    self.flush()

                    buf = buf[:-1]
                    continue
                elif char == 0x04:
                    self.writeln("quit")
                    self.flush()
                    return "quit"
            elif lenval == 3:
                if msg.value == UP_ARROW:
                    if savedcmd == None:
                        savedcmd = buf.copy()

                    self._replace_line(buf, self.lastcmd.encode("UTF-8"))

                    continue
                elif msg.value == DOWN_ARROW:
                    if savedcmd != None:
                        self._replace_line(buf, savedcmd)
                        savedcmd = None
                    continue

            buf += msg.value

            # Echo back their input.
            rmsg = BinaryMessage()
            rmsg.value = msg.value.replace(b'\n', b"\r\n")
            self.peer.protocol.write_channel_data(self.local_cid, rmsg.encode())

            i = buf.find(b'\r')
            if i == -1:
                continue

            line = buf[:i].decode()
            buf = buf[i+1:]

            return line

    def _replace_line(self, buf, newline):
        lenbuf = len(buf)
        for i in range(lenbuf):
            self.write(LEFT_ARROW)

        self.write(newline)

        diff = lenbuf - len(newline)
        if diff > 0:
            for j in range(diff):
                self.write(' ')
            for j in range(diff):
                self.write(LEFT_ARROW)

        self.flush()

        buf.clear()
        buf += newline

    def writeln(self, val):
        self.write(val)
        self._write('\n')

    def write(self, val):
        try:
            self._write(val)
        except:
            self._write(str(val))

    def _write(self, val):
        if len(val) + len(self.out_buffer) > mn1.MAX_PACKET_LENGTH:
            self.flush()

        if isinstance(val, bytearray) or isinstance(val, bytes):
            val = val.replace(b'\n', b"\r\n")
            self.out_buffer += val
        else:
            val = val.replace('\n', "\r\n")
            self.out_buffer += val.encode("UTF-8")

    def flush(self):
        if not self.out_buffer:
            return

        rmsg = BinaryMessage()
        rmsg.value = self.out_buffer
        self.peer.protocol.write_channel_data(self.local_cid, rmsg.encode())

        self.out_buffer.clear()

    def do_test(self, arg):
        "Test thing."
        self.writeln("Hello, I received your test.")

    @asyncio.coroutine
    def do_quit(self, arg):
        "Close this shell connection."
        yield from self.peer.protocol.close_channel(self.local_cid)
        return True

    def do_eval(self, arg):
        "Execute python code."
        try:
            r = eval(arg, globals(), self.shell_locals)
            self.writeln(r)
        except Exception as e:
            log.exception("eval")
            self.writeln("Exception: [{}].".format(e))

    def do_shell(self, arg):
        "Execute python code."
        try:
            exec(arg, globals(), self.shell_locals)
        except Exception as e:
            log.exception("eval")
            self.writeln("Exception: [{}].".format(e))

    def do_lp(self, arg):
        return self.do_listpeers(arg)

    def do_listpeers(self, arg):
        peers = self.peer.engine.peers
        if arg:
            if arg == 'i':
                peers = sorted(peers.values(), key=\
                    lambda peer: peer.dbid)
            elif arg == 'p':
                peers = sorted(peers.values(), key=\
                    lambda peer: peer.address.split(':')[1])
        else:
            peers = peers.values()

        
        for peer in peers:
            self.writeln(\
                "Peer: (id={} addr={}).".format(peer.dbid, peer.address))
        self.writeln("Count: {}.".format(len(peers)))

    @asyncio.coroutine
    def do_findnode(self, arg):
        "[id] find the node with hex encoded id."

        msg = chord.ChordFindNode()
        #msg.node_id = int(arg).to_bytes(512>>3, "big")
        msg.node_id = int(arg, 16).to_bytes(512>>3, "big")

        @asyncio.coroutine
        def _run_find_node(peer):
            cid, queue = yield from peer.protocol.open_channel("mpeer", True)
            if not queue:
                return

            peer.protocol.write_channel_data(cid, msg.encode())

            while True:
                pkt = yield from queue.get()
                if not pkt:
                    self.writeln("nid=[{}] EOF.".format(peer.dbid))
                    return

                pmsg = chord.ChordPeerList(pkt)

                for r in pmsg.peers:
                    r.node_id = enc.generate_ID(r.pubkey)

                    self.writeln("nid[{}] FOUND: {:22} diff=[{}]".format(peer.dbid, r.address, hex_string([x ^ y for x, y in zip(r.node_id, msg.node_id)])))
                    self.flush()

        tasks = {} # {Task, Peer}

        for peer in self.peer.engine.peers.values():
            if not peer.protocol.remote_banner.startswith("SSH-2.0-mNet_"):
                log.info("Skipping non morphis connection.")
                continue

            log.info("Sending FindNode to peer [{}].".format(peer.address))

            task = asyncio.async(_run_find_node(peer), loop=self.loop)
            tasks[task] = peer

        if not tasks:
            return

        done, pending = yield from asyncio.wait(\
            tasks.keys(), loop=self.loop, timeout=2)

        for pend in pending:
            self.writeln("note: Peer (id={}) didn't finish by timeout."\
                .format(tasks[pend].dbid))

    @asyncio.coroutine
    def do_conn(self, arg):
        r = yield from self.peer.engine.connect_peer(arg)
        self.writeln(r)

    @asyncio.coroutine
    def do_st(self, arg):
        cnt = 0
        try:
            for task in asyncio.Task.all_tasks(loop=self.loop):
                task_str = str(task)
                if "_process_ssh_protocol" in task_str\
                        or "_process_chord_packet" in task_str\
                        or "_shell_exec" in task_str\
                        or "_connection_lost" in task_str\
                        or "cmdloop" in task_str:
                    continue
                self.writeln("Task [{}]:".format(task))
                task.print_stack(file=self)
                cnt += 1
        except:
            log.exception("Task")

        self.writeln("Count: {}.".format(cnt))

    @asyncio.coroutine
    def do_sta(self, arg):
        cnt = 0
        try:
            for task in asyncio.Task.all_tasks(loop=self.loop):
                self.writeln("Task [{}]:".format(task))
                task.print_stack(file=self)
                cnt += 1
        except:
            log.exception("Task")

        self.writeln("Count: {}.".format(cnt))

    @asyncio.coroutine
    def do_listchans(self, arg):
        "List the open channels of all connected PeerS."

        code = "list(filter(lambda x: x[1], map(lambda node: [node.bind_address, list(filter(lambda x: x[1], map(lambda peer: [peer.address, list(peer.protocol._channel_map.items())], node.chord_engine.peers.values())))], self.peer.engine.node.all_nodes)))"
        return self.do_eval(code)

    def emptyline(self):
        pass

class BinaryMessage():
    def __init__(self, buf = None):
        self.buf = buf

        self.value = None

        if buf:
            self.parse()

    def encode(self):
        nbuf = bytearray()

        nbuf += sshtype.encodeBinary(self.value)

        return nbuf

    def parse(self):
        i = 1
        l, self.value = sshtype.parseBinary(self.buf)
