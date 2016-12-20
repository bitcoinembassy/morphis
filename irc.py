# Höfundarréttur (c) eilífur  Heimur-Heilinn
# License: GPL v2.

import llog

import asyncio
from enum import Enum
import logging

log = logging.getLogger(__name__)

class Status(Enum):
    new = 0
    ready = 10
    closed = 20
    disconnected = 30

class IrcProtocol(asyncio.Protocol):
    def __init__(self, loop):
        self.loop = loop

        self.address = None # (host, port)

        self.transport = None

        self.server_mode = None

        self.status = Status.new

