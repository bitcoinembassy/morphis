import llog

import asyncio
import logging
import os

import packet as mnetpacket
import rsakey
import mn1
from mutil import hex_dump
import chord
import peer

log = logging.getLogger(__name__)

class Peer():
    def __init__(self, engine):
        self.engine = engine

        self.dbid = None

        self.protocol_handler = None

        self.node_key = None
        self.channel_handler = ChannelHandler(self)
        self.connection_handler = ConnectionHandler(self)

    def get_protocol_handler(self):
        return self.protocol_handler

    def set_protocol_handler(self, value):
        self.protocol_handler = value

        self.protocol_handler.set_channel_handler(self.channel_handler)
        self.protocol_handler.set_connection_handler(self.connection_handler)

class ConnectionHandler():
    def __init__(self, peer):
        self.peer = peer

    def connection_made(self, p):
        self.peer.engine.connection_made(self.peer)

    def error_recieved(self, p, exc):
        pass

    def connection_lost(self, p, exc):
        self.peer.engine.connection_lost(self.peer, exc)

class ChannelHandler():
    def __init__(self, peer):
        self.peer = peer

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
