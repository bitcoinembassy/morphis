# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import asyncio
import json
import logging
import os
import struct

import brute
import chord
import mbase32
import multipart as mp
import mutil
import dhgroup14
import enc
import sshtype
import rsakey

log = logging.getLogger(__name__)

_dh_method_name = "mdh-v1"

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

        self.root["ssm"] = _dh_method_name
        self.root["sse"] = dh.e

    def generate(self):
        self.generate_target()
        self.generate_ss()

    def export(self):
        return json.dumps(self.root).encode()

class DmailWrapper(object):
    def __init__(self):
        self.version = 1
        self.ssm = None
        self.sse = None
        self.ssf = None

        self.data = None
        self.data_len = None
        self.data_enc = None
        self.data_enc2 = None

    def encode(self, obuf=None):
        buf = obuf if obuf else bytearray()

        buf += struct.pack("B", self.version)
        buf += sshtype.encodeString(self.ssm)
        buf += sshtype.encodeMpint(self.sse)
        buf += sshtype.encodeMpint(self.ssf)
        buf += struct.pack(">L", self.data_len)
        buf += self.data_enc
        if self.data_enc2:
            buf += self.data_enc2

class Dmail(object):
    def __init__(self):
        self.version = 1
        self.sender_pubkey = None
        self.subject = None
        self.parts = [] # [DmailPart].

    def encode(self, obuf=None):
        buf = obuf if obuf else bytearray()

        buf += struct.pack(">L", self.version)
        buf += sshtype.encodeBinary(self.sender_pubkey)
        buf += sshtype.encodeString(self.subject)

        buf += struct.pack(">L", len(self.parts))
        for part in self.parts:
            part.encode(buf)

        return buf

class DmailPart(object):
    def __init__(self):
        self.mime = None
        self.data = None

    def encode(self, obuf=None):
        buf = obuf if obuf else bytearray()
        buf += sshtype.encodeString(self.mime)
        buf += sshtype.encodeBinary(self.data)
        return buf

    def parse_from(self, buf, idx):
        l, self.mime = sshtype.parse_string_from(buf, idx)
        idx += l
        l, self.data = sshtype.parse_binary_from(buf, idx)
        idx += l
        return idx

class DmailEngine(object):
    def __init__(self, task_engine):
        self.task_engine = task_engine

    @asyncio.coroutine
    def send_dmail_text(self, subject, message_text):
        if message_text.startswith("from: "):
            p0 = message_text.find('\n')
            m_from_pubkey = mbase32.decode(message_text[6:p0])
            p0 += 1
        else:
            p0 = 0
            m_from_pubkey = b""

        m_dest_ids = []
        while message_text.startswith("to: ", p0):
            p1 = message_text.find('\n')
            m_dest = message_text[p0+4:p1]
            m_dest_id = mbase32.decode(m_dest)
            m_dest_ids.append(m_dest_id)
            p0 = p1 + 1

        part = DmailPart()
        part.mime = "text/plain"
        part.data = message_text[p0:].encode()

        dmail = Dmail()
        dmail.sender_pubkey = m_from_pubkey
        dmail.subject = subject
        dmail.parts.append(part)

        if log.isEnabledFor(logging.INFO):
            log.info("len(m_dest_ids)=[{}].".format(len(m_dest_ids)))

        yield from self.send_dmail(dmail, m_dest_ids)

    @asyncio.coroutine
    def send_dmail(self, dmail, recipients):
        assert type(dmail) is Dmail, type(dmail)

        dmail_bytes = dmail.encode()

        recipients = yield from self._fetch_recipient_dmail_sites(recipients)

        for recipient in recipients:
            if recipient.root["ssm"] != _dh_method_name:
                raise Exception("Unsupported ss method [{}]."\
                    .format(recipient.root["ssm"]))

            yield from self._send_dmail(dmail, recipient)

    @asyncio.coroutine
    def _send_dmail(self, dmail, recipient):
        root = recipient.root
        sse = root["sse"]
        target = root["target"]
        difficulty = root["difficulty"]

        dh = dhgroup14.DhGroup14()
        dh.generate_x()
        dh.generate_e()
        dh.f = sse

        k = dh.calculate_k()

        target_id = mbase32.decode(target)

        key = enc.generate_ID(\
            target_id + sshtype.encodeMpint(k) + dmail.sender_pubkey)

        dmail_bytes = dmail.encode()
        m, r = enc.encrypt_data_block(dmail_bytes, key)

        dw = DmailWrapper()
        dw.ssm = _dh_method_name
        dw.sse = sse
        dw.ssf = dh.e
        dw.data_len = len(dmail_bytes)
        dw.data_enc = m
        dw.data_enc2 = r

        tb = mp.TargetedBlock()
        tb.target = target_id
        tb.noonce = int(0).to_bytes(64, "big")
        tb.block = dw

        data = tb.encode()

        if log.isEnabledFor(logging.INFO):
            log.info(\
                "Attempting work on dmail (target=[{}], difficulty=[{}])."\
                    .format(target, difficulty))

        noonce_bytes = brute.generate_targeted_block(\
            target_id, difficulty, data,\
            mp.TargetedBlock.NOONCE_OFFSET,\
            mp.TargetedBlock.NOONCE_SIZE)

        if log.isEnabledFor(logging.INFO):
            log.info("Work found noonce [{}].".format(noonce_bytes))

        mp.TargetedBlock.set_noonce(data, noonce_bytes)

        if log.isEnabledFor(logging.INFO):
            log.info(\
                "hash=[{}].".format(mbase32.encode(enc.generate_ID(data))))

        key = None

        def key_callback(val):
            nonlocal key
            key = val

        log.info("Sending dmail to the network.")

        if log.isEnabledFor(logging.DEBUG):
            log.debug("dmail block data=[\n{}].".format(mutil.hex_dump(data)))

        storing_nodes = yield from\
            self.task_engine.send_store_data(\
                data, store_key=True, key_callback=key_callback)

        key_enc = mbase32.encode(key)
        id_enc = mbase32.encode(enc.generate_ID(key))

        if log.isEnabledFor(logging.INFO):
            log.info("Dmail sent; key=[{}], id=[{}], storing_nodes=[{}]."\
                .format(key_enc, id_enc, storing_nodes))

    @asyncio.coroutine
    def _fetch_recipient_dmail_sites(self, recipients):
        robjs = []

        for recipient in recipients:
            data_rw = yield from self.task_engine.send_get_data(recipient)

            if not data_rw.data:
                if log.isEnabledFor(logging.INFO):
                    log.info("Failed to fetch dmail site [{}]."\
                        .format(mbase32.encode(recipient)))
                continue

            site_data = data_rw.data.decode("UTF-8")

            if log.isEnabledFor(logging.INFO):
                log.info("site_data=[{}].".format(site_data))

            robjs.append(DmailSite(site_data))

        return robjs
