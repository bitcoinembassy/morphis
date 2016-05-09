
# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
from datetime import datetime
import json
import logging
import os
import struct
import time

from sqlalchemy import func

import base58
import brute
import chord
import consts
import db
import mbase32
import multipart as mp
import mutil
import dhgroup14
import enc
import sshtype
import rsakey

log = logging.getLogger(__name__)

_dh_method_name = "mdh-v1"

class DpushException(Exception):
    pass

class DpushSite(object):
    def __init__(self, prev=None):
        self.root = json.loads(prev) if prev else {}

    def generate_target(self):
        target = os.urandom(chord.NODE_ID_BYTES)

        if log.isEnabledFor(logging.INFO):
            log.info("DpushSite target=[{}].".format(mbase32.encode(target)))

        self.root["target"] = mbase32.encode(target)

    def generate(self):
        self.generate_target()

    def export(self):
        return json.dumps(self.root).encode()
