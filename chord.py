import llog

import asyncio
import logging
import os

import packet as mnetpacket
import rsakey
import mn1
from mutil import hex_dump

log = logging.getLogger(__name__)

class ChordEngine():
    def __init__(self, node):
        self.node = node

        self.server = None
        self.server_protocol = None
        self.ch = ChannelHandler()

    def start(self):
        host, port = "127.0.0.1", 5555
        self.server = self.node.get_loop().create_server(self._create_server_protocol, host, port)
        self.node.get_loop().run_until_complete(self.server)
        log.info("Node listening on [{}:{}].".format(host, port))

    def stop(self):
        self.server.close()

    def _create_server_protocol(self):
        p = mn1.SshServerProtocol(self.node.get_loop(), self.ch)
        p.set_server_key(self.node.get_node_key())
        return p

class ChannelHandler():
    @asyncio.coroutine
    def open_channel(self, protocol, packet):
        m = mnetpacket.SshChannelOpenMessage(packet)
        log.info("S: Received CHANNEL_OPEN: channel_type=[{}], sender_channel=[{}].".format(m.get_channel_type(), m.get_sender_channel()))

        cm = mnetpacket.SshChannelOpenConfirmationMessage()
        cm.set_recipient_channel(m.get_sender_channel())
        cm.set_sender_channel(0)
        cm.set_initial_window_size(65535)
        cm.set_maximum_packet_size(65535)

        cm.encode()

        protocol.write_packet(cm)

    @asyncio.coroutine
    def data(self, protocol, packet):
        m = mnetpacket.SshChannelDataMessage(packet)
        log.debug("Received data, recipient_channel=[{}], value=[\n{}].".format(m.get_recipient_channel(), hex_dump(m.get_data())))


