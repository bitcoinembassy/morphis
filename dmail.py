import llog

import asyncio
import json
import logging
import os

import mbase32
import chord
import dhgroup14
import rsakey

log = logging.getLogger(__name__)

class DmailSite(object):
    def __init__(self, prev=None):
        self.root = json.loads(prev) if prev else {}

        self.dh = None

    def generate_target(self):
        target = os.urandom(chord.NODE_ID_BYTES)

        if log.isEnabledFor(logging.INFO):
            log.info("dmail target=[{}].".format(mbase32.encode(target)))

        self.root["target"] = mbase32.encode(target)
        self.root["difficulty"] = 20 # 1048576 hashes on average.

    def generate_ss(self):
        self.dh = dh = dhgroup14.DhGroup14()
        dh.generate_x()
        dh.generate_e()

        if log.isEnabledFor(logging.INFO):
            log.info("dmail e=[{}].".format(dh.e))

        self.root["ssm"] = "mdh-v1"
        self.root["sse"] = dh.e

    def generate(self):
        self.generate_target()
        self.generate_ss()

    def export(self):
        return json.dumps(self.root).encode()
