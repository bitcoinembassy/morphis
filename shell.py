# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
import cmd
from datetime import datetime
import logging
import queue as tqueue

import base58
import chord
import db
import enc
import mbase32
import mn1
import multipart
from mutil import hex_dump, hex_string, decode_key, calc_raw_distance
import node
import rsakey
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
        if line and line[0] == ';':
            for line in line.split(';'):
                log.info("line=[{}].".format(line))
                stop = yield from self._onecmd(line)
                if stop:
                    return True
        else:
            return (yield from self._onecmd(line))

    @asyncio.coroutine
    def _onecmd(self, line):
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

        try:
            if asyncio.iscoroutinefunction(func):
                r = yield from func(arg)
                return r
            else:
                return func(arg)
        except Exception as e:
            self.writeln("Exception [{}] executing command.".format(e))
            log.exception("func(arg)")

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

            #TODO: Replace this hacky code that handle multibyte characters
            # with something better. This lets you type one and hit enter
            # without it breaking, but if you type one and hit backspace then
            # you are still doomed until you press CTRL-D to quit.
            i = 0
            while True:
                i = buf.find(b'\r', i)
                if i == -1:
                    outer_continue = True
                    break

                try:
                    line = buf[:i].decode()
                except Exception:
                    i += 1
                    continue

                buf = buf[i+1:]

                return line

            if outer_continue:
                outer_continue = False
                continue

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
        except Exception:
            self._write(str(val))

    def write_raw(self, val):
        assert type(val) in (bytes, bytearray), type(val)

        self.out_buffer += val

        if len(self.out_buffer) > mn1.MAX_PACKET_LENGTH:
            self.flush()

    def _write(self, val):
        if isinstance(val, bytearray) or isinstance(val, bytes):
            val = val.replace(b'\n', b"\r\n")
            self.out_buffer += val
        else:
            val = val.replace('\n', "\r\n")
            self.out_buffer += val.encode("UTF-8")

        if len(self.out_buffer) > mn1.MAX_PACKET_LENGTH:
            self.flush()

    def flush(self):
        if not self.out_buffer:
            return

        while True:
            outbuf = self.out_buffer
            if len(outbuf) > mn1.MAX_PACKET_LENGTH:
                outbuf = outbuf[:mn1.MAX_PACKET_LENGTH]
                self.out_buffer = outbuf[mn1.MAX_PACKET_LENGTH:]

            rmsg = BinaryMessage()
            rmsg.value = outbuf
            self.peer.protocol.write_channel_data(self.local_cid, rmsg.encode())

            if outbuf is self.out_buffer:
                self.out_buffer.clear()
                break

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

        if not self.peer.engine.node.eval_enabled:
            self.writeln("Eval is disabled.")
            return

        try:
            r = eval(arg, globals(), self.shell_locals)
            self.writeln(r)
        except Exception as e:
            log.exception("eval")
            self.writeln("Exception: [{}].".format(e))

    def do_shell(self, arg):
        "Execute python code."

        if not self.peer.engine.node.eval_enabled:
            self.writeln("Eval is disabled.")
            return

        try:
            exec(arg, globals(), self.shell_locals)
        except Exception as e:
            log.exception("eval")
            self.writeln("Exception: [{}].".format(e))

    def do_lp(self, arg):
        "listpeers alias."
        return self.do_listpeers(arg)

    def do_listpeers(self, arg):
        "List connected PeerS."
        peers = self.peer.engine.peers.values()

        if arg:
            if arg == 'i':
                peers = sorted(peers, key=\
                    lambda peer: peer.dbid)
            elif arg == 'd':
                peers = sorted(peers, key=\
                    lambda peer: peer.distance)
            elif arg == 'p':
                peers = sorted(peers, key=\
                    lambda peer: peer.address.split(':')[1])
        
        for peer in peers:
            self.writeln(\
                "Peer: (id={} addr={}, distance={})."\
                    .format(peer.dbid, peer.address, peer.distance))
        self.writeln("Count: {}.".format(len(peers)))

    @asyncio.coroutine
    def do_fn(self, arg):
        "findnode alias."
        yield from self.do_findnode(arg)

    @asyncio.coroutine
    def do_findnode(self, arg):
        "[ID] find the node with id."

        node_id, significant_bits = decode_key(arg)

        if significant_bits:
            self.writeln("Won't FindNode for incomplete key.")
            return

        start = datetime.today()
        result = yield from self.peer.engine.tasks.send_find_node(node_id)
        diff = datetime.today() - start
        self.writeln("send_find_node(..) took: {}.".format(diff))

        for r in result:
            self.writeln("nid[{}] FOUND: {:22} id=[{}] diff=[{}]"\
                .format(r.id, r.address, hex_string(r.node_id),\
                    hex_string(\
                        calc_raw_distance(\
                            r.node_id, node_id))))

    @asyncio.coroutine
    def do_gd(self, arg):
        "getdata alias."
        yield from self.do_getdata(arg)

    @asyncio.coroutine
    def do_getdata(self, arg):
        "<DATA_KEY> [PATH] retrieve data for DATA_KEY from the network."

        args = arg.split(' ')

        data_key, significant_bits = decode_key(args[0])
        path = args[1].encode() if len(args) == 2 else None

        if significant_bits:
            self.writeln("Incomplete key, use findkey.")
            return

        start = datetime.today()
        data_rw =\
            yield from multipart.get_data_buffered(\
                self.peer.engine, data_key, path=path)
        diff = datetime.today() - start

        self.writeln("send_get_data(..) took: {}.".format(diff))
        self.writeln("version=[{}].".format(data_rw.version))
        self.writeln("data:")
        if data_rw.data is not None:
            self.write_raw(data_rw.data)
            self.writeln("")
        else:
            self.writeln("Not found.")

    @asyncio.coroutine
    def do_gettargeteddata(self, arg):
        "<DATA_KEY> retrieve targeted data for DATA_KEY from the network."

        data_key, significant_bits = decode_key(arg)

        if significant_bits:
            self.writeln("Incomplete key, use findkey.")
            return

        start = datetime.today()
        data_rw =\
            yield from self.peer.engine.tasks.send_get_targeted_data(data_key)
        diff = datetime.today() - start

        self.writeln("send_get_targeted_data(..) took: {}.".format(diff))

        if data_rw.data is not None:
            self.writeln("data:")
            self.write_raw(data_rw.data)
            self.writeln("")
        else:
            self.writeln("Not found.")

    @asyncio.coroutine
    def do_fk(self, arg):
        "findkey alias."
        yield from self.do_findkey(arg)

    @asyncio.coroutine
    def do_findkey(self, arg):
        "<DATA_KEY_PREFIX> [TARGET_ID] [SIGNIFICANT_BITS] search the network"
        " for the given key."

        args = arg.split(' ')

        data_key, significant_bits = decode_key(args[0])
        target_key = mbase32.decode(args[1]) if len(args) >= 2 else None
        if len(args) == 3:
            significant_bits = int(args[2])

        start = datetime.today()
        data_rw = yield from\
            self.peer.engine.tasks.send_find_key(\
                data_key, significant_bits=significant_bits,\
                    target_key=target_key)
        diff = datetime.today() - start
        data_key_enc =\
            mbase32.encode(data_rw.data_key) if data_rw.data_key else None
        self.writeln("data_key=[{}].".format(data_key_enc))
        self.writeln("send_find_key(..) took: {}.".format(diff))

    @asyncio.coroutine
    def do_storeblockenc(self, arg):
        "<data> store base58 encoded block."

        args = arg.split(' ')

        data = base58.decode(args[0])
        store_key = bool(args[1]) if len(args) == 2 else False

        def key_callback(data_key):
            self.writeln("data_key=[{}].".format(mbase32.encode(data_key)))

        start = datetime.today()

        storing_nodes =\
            yield from self.peer.engine.tasks.send_store_data(\
                data, store_key=store_key, key_callback=key_callback)

        diff = datetime.today() - start
        self.writeln("storing_nodes=[{}].".format(storing_nodes))
        self.writeln("send_store_data(..) took: {}.".format(diff))

    @asyncio.coroutine
    def do_storetargetedblockenc(self, arg):
        "<data> store base58 encoded targeted block."

        args = arg.split(' ')

        data = base58.decode(args[0])
        store_key = bool(args[1]) if len(args) == 2 else False

        def key_callback(data_key):
            self.writeln("data_key=[{}].".format(mbase32.encode(data_key)))

        start = datetime.today()

        storing_nodes =\
            yield from self.peer.engine.tasks.send_store_targeted_data(\
                data, store_key=store_key, key_callback=key_callback)

        diff = datetime.today() - start
        self.writeln("storing_nodes=[{}].".format(storing_nodes))
        self.writeln("send_store_targeted_data(..) took: {}.".format(diff))

    @asyncio.coroutine
    def do_storedataenc(self, arg):
        "<data> store base58 encoded data."

        data = base58.decode(arg)

        def key_callback(data_key):
            self.writeln("data_key=[{}].".format(mbase32.encode(data_key)))

        start = datetime.today()

        yield from multipart.store_data(\
            self.peer.engine, data, key_callback=key_callback)

        diff = datetime.today() - start
        self.writeln("multipart.store_data(..) took: {}.".format(diff))

    @asyncio.coroutine
    def do_storeukeyenc(self, arg):
        "<KEY> <DATA> <VERSION> <STOREKEY> [PATH] store base58 encoded DATA"
        " with base58 encoded private KEY."

        args = arg.split(' ')

        key = rsakey.RsaKey(privdata=base58.decode(args[0]))
        data = base58.decode(args[1])
        version = int(args[2])
        storekey = bool(args[3])
        path = args[4] if len(args) > 4 else None

        def key_callback(data_key):
            self.writeln("data_key=[{}].".format(mbase32.encode(data_key)))

        start = datetime.today()

        yield from multipart.store_data(\
            self.peer.engine, data, privatekey=key, path=path,\
            version=version, key_callback=key_callback)

        diff = datetime.today() - start
        self.writeln("multipart.store_data(..) took: {}.".format(diff))

    @asyncio.coroutine
    def do_sd(self, arg):
        "storedata alias."
        yield from self.do_storedata(arg)

    @asyncio.coroutine
    def do_storedata(self, arg):
        "<DATA> store DATA into the network."

        data = bytes(arg, 'UTF8')

        max_len = node.MAX_DATA_BLOCK_SIZE

        if len(data) > max_len:
            self.writeln("ERROR: data cannot be greater than {} bytes."\
                .format(max_len))
            return

        def key_callback(data_key):
            self.writeln("data_key=[{}].".format(mbase32.encode(data_key)))

        start = datetime.today()
        storing_nodes =\
            yield from self.peer.engine.tasks.send_store_data(\
                data, key_callback=key_callback)
        diff = datetime.today() - start
        self.writeln("storing_nodes=[{}].".format(storing_nodes))
        self.writeln("send_store_data(..) took: {}.".format(diff))

    @asyncio.coroutine
    def do_sk(self, arg):
        "storekey alias."
        yield from self.do_storekey(arg)

    @asyncio.coroutine
    def do_storekey(self, arg):
        "<DATA> store DATA's key into the network."

        data = bytes(arg, "UTF8")

        max_len = node.MAX_DATA_BLOCK_SIZE

        if len(data) > max_len:
            self.writeln("ERROR: data cannot be greater than {} bytes."\
                .format(max_len))
            return

        def key_callback(data_key):
            self.writeln("data_key=[{}].".format(mbase32.encode(data_key)))

        start = datetime.today()
        storing_nodes =\
            yield from self.peer.engine.tasks.send_store_key(\
                data, key_callback=key_callback)
        diff = datetime.today() - start
        self.writeln("storing_nodes=[{}].".format(storing_nodes))
        self.writeln("send_store_key(..) took: {}.".format(diff))

    @asyncio.coroutine
    def do_conn(self, arg):
        "Connect to the passed address as a Peer."
        r = yield from self.peer.engine.connect_peer(arg)
        self.writeln(r)

    @asyncio.coroutine
    def do_st(self, arg):
        "Print out current eventloop TaskS (filtering uninteresting ones)."
        cnt = 0
        try:
            for task in asyncio.Task.all_tasks(loop=self.loop):
                task_str = str(task)
                if "_process_ssh_protocol" in task_str\
                        or "_shell_exec" in task_str\
                        or "_connection_lost" in task_str\
                        or "cmdloop" in task_str:
                    continue
                self.writeln("Task [{}]:".format(task))
                task.print_stack(file=self)
                cnt += 1
        except Exception:
            errmsg = "Exception printing tasks."
            log.exception(errmsg)
            self.writeln(errmsg)

        self.writeln("Count: {}.".format(cnt))

    @asyncio.coroutine
    def do_sta(self, arg):
        "Print out current eventloop TaskS (unfiltered)."
        cnt = 0
        try:
            for task in asyncio.Task.all_tasks(loop=self.loop):
                self.writeln("Task [{}]:".format(task))
                task.print_stack(file=self)
                cnt += 1
        except Exception:
            errmsg = "Exception printing tasks."
            log.exception(errmsg)
            self.writeln(errmsg)

        self.writeln("Count: {}.".format(cnt))

    @asyncio.coroutine
    def do_lc(self, arg):
        "listchans alias."
        return (yield from self.do_listchans(arg))

    @asyncio.coroutine
    def do_listchans(self, arg):
        "List the open channels of all connected PeerS."

        code = "list(filter(lambda x: x[1], map(lambda peer: [peer.address, list(peer.protocol._channel_map.items())], self.peer.engine.node.chord_engine.peers.values())))"
        return self.do_eval(code)

    @asyncio.coroutine
    def do_stat(self, arg):
        "Report the node status."

        engine = self.peer.engine

        self.writeln("Node:\n\tversion=[{}]\n\tid=[{}]\n\tbind_port=[{}]\n"\
            "\tconnections={}"\
                .format(engine.node.morphis_version,\
                    mbase32.encode(engine.node_id), engine._bind_port,\
                    len(engine.peers)))

    @asyncio.coroutine
    def do_time(self, arg):
        "Time the passed command line (wrapping call)."

        start = datetime.today()
        r = yield from self.onecmd(arg)
        diff = datetime.today() - start

        self.writeln("Timed command took: {}.".format(diff))

        self.lastcmd = "time " + arg

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
