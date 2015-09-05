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

class DmailException(Exception):
    pass

class DmailSite(object):
    def __init__(self, prev=None):
        self.root = json.loads(prev) if prev else {}

        self.dh = None

    def generate_target(self):
        target = os.urandom(chord.NODE_ID_BYTES)

        if log.isEnabledFor(logging.INFO):
            log.info("dmail target=[{}].".format(mbase32.encode(target)))

        self.root["target"] = mbase32.encode(target)

    def generate_ss(self):
        self.dh = dh = dhgroup14.DhGroup14()
        dh.generate_x()
        dh.generate_e()

        if log.isEnabledFor(logging.INFO):
            log.info("dmail e=[{}].".format(dh.e))

        self.root["ssm"] = _dh_method_name
        self.root["sse"] = base58.encode(sshtype.encodeMpint(dh.e))

    def generate(self):
        self.generate_target()
        self.generate_ss()

    def export(self):
        return json.dumps(self.root).encode()

class DmailWrapperV1(object):
    def __init__(self, buf=None, offset=0):
        self.version = 1
        self.ssm = None
        self.sse = None
        self.ssf = None

        self.signature = None

        self.data = None
        self.data_len = None
        self.data_enc = None

        if buf is not None:
            self.parse_from(buf, offset)

    def encode(self, obuf=None):
        buf = obuf if obuf else bytearray()
        buf += struct.pack(">L", self.version)
        buf += sshtype.encodeString(self.ssm)
        buf += sshtype.encodeMpint(self.sse)
        buf += sshtype.encodeMpint(self.ssf)

        buf += sshtype.encodeBinary(self.signature)

        buf += struct.pack(">L", self.data_len)
        buf += self.data_enc

    def parse_from(self, buf, idx):
        self.version = struct.unpack_from(">L", buf, idx)[0]
        idx += 4
        idx, self.ssm = sshtype.parse_string_from(buf, idx)
        idx, self.sse = sshtype.parse_mpint_from(buf, idx)
        idx, self.ssf = sshtype.parse_mpint_from(buf, idx)

        idx, self.signature = sshtype.parse_binary_from(buf, idx)

        self.data_len = struct.unpack_from(">L", buf, idx)[0]
        idx += 4

        self.data_enc = buf[idx:]

        return idx

class DmailWrapper(object):
    def __init__(self, buf=None, offset=0):
        self.version = 2
        self.ssm = None
        self.sse = None
        self.ssf = None

        self.data = None
        self.data_len = None
        self.data_enc = None

        if buf is not None:
            self.parse_from(buf, offset)

    def encode(self, obuf=None):
        buf = obuf if obuf else bytearray()
        buf += struct.pack(">L", self.version)
        buf += sshtype.encodeString(self.ssm)
        buf += sshtype.encodeMpint(self.sse)
        buf += sshtype.encodeMpint(self.ssf)

        buf += struct.pack(">L", self.data_len)
        buf += self.data_enc

    def parse_from(self, buf, idx):
        self.version = struct.unpack_from(">L", buf, idx)[0]
        idx += 4
        idx, self.ssm = sshtype.parse_string_from(buf, idx)
        idx, self.sse = sshtype.parse_mpint_from(buf, idx)
        idx, self.ssf = sshtype.parse_mpint_from(buf, idx)

        self.data_len = struct.unpack_from(">L", buf, idx)[0]
        idx += 4

        self.data_enc = buf[idx:]

        return idx

class DmailV1(object):
    def __init__(self, buf=None, offset=0, length=None):
        self.version = 1
        self.sender_pubkey = None
        self.subject = None
        self.date = None
        self.parts = [] # [DmailPart].

        if buf:
            self.parse_from(buf, offset, length)

    def encode(self, obuf=None):
        buf = obuf if obuf else bytearray()

        buf += struct.pack(">L", self.version)
        buf += sshtype.encodeBinary(self.sender_pubkey)
        buf += sshtype.encodeString(self.subject)
        buf += sshtype.encodeString(self.date)

        for part in self.parts:
            part.encode(buf)

        return buf

    def parse_from(self, buf, idx, length=None):
        if not length:
            length = len(buf)

        self.version = struct.unpack_from(">L", buf, idx)[0]
        idx += 4
        idx, self.sender_pubkey = sshtype.parse_binary_from(buf, idx)
        idx, self.subject = sshtype.parse_string_from(buf, idx)
        idx, self.date = sshtype.parse_string_from(buf, idx)

        while idx < length:
            part = DmailPart()
            idx = part.parse_from(buf, idx)
            self.parts.append(part)

        return idx

class Dmail(object):
    def __init__(self, buf=None, offset=0):
        self.buf = buf

        self.version = 2
        self.sender_pubkey = None
        self.destination_addr = None
        self.subject = None
        self.date = None
        self.parts = [] # [DmailPart].

        self.signature_offset = None
        self.signature = None

        if buf:
            self.parse_from(buf, offset)

    def encode(self, obuf=None):
        self.buf = buf = obuf if obuf else bytearray()

        buf += struct.pack(">L", self.version)
        buf += sshtype.encodeBinary(self.sender_pubkey)
        buf += sshtype.encodeBinary(self.destination_addr)
        buf += sshtype.encodeString(self.subject)
        buf += sshtype.encodeString(self.date)

        buf += struct.pack(">H", len(self.parts))
        for part in self.parts:
            part.encode(buf)

        self.signature_offset = len(buf)

        # Reserve space for signature, MorphisBlock and TargetedBlock header.
        max_size = consts.MAX_DATA_BLOCK_SIZE - 2768

        if len(buf) > max_size:
            raise DmailException(\
                "Dmail is [{}] bytes, yet cannot be larger than [{}] bytes."\
                    .format(len(buf), max_size))

        # 512 byte RSA-4096 signature goes at the end.

        return buf

    def parse_from(self, buf, idx):
        self.version = struct.unpack_from(">L", buf, idx)[0]
        idx += 4
        idx, self.sender_pubkey = sshtype.parse_binary_from(buf, idx)
        idx, self.destination_addr = sshtype.parse_binary_from(buf, idx)
        idx, self.subject = sshtype.parse_string_from(buf, idx)
        idx, self.date = sshtype.parse_string_from(buf, idx)

        part_cnt = struct.unpack_from(">H", buf, idx)[0]
        idx += 2

        for i in range(part_cnt):
            part = DmailPart()
            idx = part.parse_from(buf, idx)
            self.parts.append(part)

        self.signature_offset = idx
        idx, self.signature = sshtype.parse_binary_from(buf, idx)

        return idx

class DmailPart(object):
    def __init__(self):
        self.mime_type = None
        self.data = None

    def encode(self, obuf=None):
        buf = obuf if obuf else bytearray()
        buf += sshtype.encodeString(self.mime_type)
        buf += sshtype.encodeBinary(self.data)
        return buf

    def parse_from(self, buf, idx):
        idx, self.mime_type = sshtype.parse_string_from(buf, idx)
        idx, self.data = sshtype.parse_binary_from(buf, idx)
        return idx

class DmailEngine(object):
    def __init__(self, task_engine, db):
        self.task_engine = task_engine
        self.db = db
        self.loop = task_engine.loop

    @asyncio.coroutine
    def generate_dmail_address(self, prefix=None, difficulty=20):
        assert type(difficulty) is int

        if log.isEnabledFor(logging.INFO):
            log.info("Generating dmail address (prefix=[{}].".format(prefix))

        def threadcall():
            if prefix:
                if log.isEnabledFor(logging.INFO):
                    log.info("Brute force generating key with prefix [{}]."\
                        .format(prefix))
                return brute.generate_key(prefix)
            else:
                return rsakey.RsaKey.generate(bits=4096)

        privkey = yield from self.loop.run_in_executor(None, threadcall)

        dms = DmailSite()
        dms.generate()
        dms.root["difficulty"] = difficulty

        data_key = None
        def key_callback(value):
            nonlocal data_key
            data_key = value

        log.info("Uploading dmail site.")

        total_storing = yield from self.publish_dmail_site(\
                privkey, dms, key_callback=key_callback)

        def dbcall():
            with self.db.open_session() as sess:
                dmailaddress = db.DmailAddress()
                dmailaddress.site_key = data_key
                dmailaddress.site_privatekey = privkey._encode_key()
                dmailaddress.scan_interval = 60

                dmailkey = db.DmailKey()
                dmailkey.x = sshtype.encodeMpint(dms.dh.x)
                dmailkey.target_key = mbase32.decode(dms.root["target"])
                dmailkey.difficulty = difficulty

                dmailaddress.keys.append(dmailkey)

                sess.add(dmailaddress)
                sess.commit()

        log.info("Saving dmail site to the database.")

        yield from self.loop.run_in_executor(None, dbcall)

        return privkey, data_key, dms, total_storing

    @asyncio.coroutine
    def publish_dmail_site(self, privkey, dmail_site, key_callback=None):
        dms_data = dmail_site.export()

        total_storing = 0
        retry = 0
        while True:
            storing_nodes = yield from\
                self.task_engine.send_store_updateable_key(\
                    dms_data, privkey, version=int(time.time()*1000),\
                    store_key=True, key_callback=key_callback,\
                    retry_factor=retry * 20)

            total_storing += storing_nodes

            if total_storing >= 3:
                break

            if retry > 32:
                break
            elif retry > 3:
                yield from asyncio.sleep(1)

            retry += 1

        return total_storing

    @asyncio.coroutine
    def send_dmail_text(self, subject, message_text):
        if message_text.startswith("from: "):
            p0 = message_text.find('\n')
            m_from_asymkey = rsakey.RsaKey(\
                privdata=base58.decode(message_text[6:p0]))
            p0 += 1
        else:
            p0 = 0
            m_from_asymkey = None

        m_dest_ids = []
        while message_text.startswith("to: ", p0):
            p1 = message_text.find('\n')
            m_dest_enc = message_text[p0+4:p1]
            m_dest_id, sig_bits = mutil.decode_key(m_dest_enc)
            m_dest_ids.append((m_dest_enc, m_dest_id, sig_bits))
            p0 = p1 + 1

        date = mutil.utc_datetime()

        if message_text[p0] == '\n':
            p0 += 1

        message_text = message_text[p0:]

        storing_nodes = 0

        for dest_id in m_dest_ids:
            storing_nodes += yield from self.send_dmail(\
                m_from_asymkey, dest_id, subject, date, message_text)

        return storing_nodes

    @asyncio.coroutine
    def send_dmail(self, from_asymkey, destination_addr, subject, date,\
            message_text):
        assert from_asymkey is None or type(from_asymkey) is rsakey.RsaKey
        assert type(destination_addr) in (list, tuple, bytes, bytearray, str),\
            type(destination_addr)
        assert not date or type(date) is datetime

        addr, rsite =\
            yield from self.fetch_recipient_dmail_site(destination_addr)

        if not rsite:
            return False

        if rsite.root["ssm"] != _dh_method_name:
            raise DmailException("Unsupported ss method [{}]."\
                .format(rsite.root["ssm"]))

        if type(message_text) is str:
            message_text = message_text.encode()
        if not date:
            date = mutil.utc_datetime()

        dmail = Dmail()
        dmail.sender_pubkey = from_asymkey.asbytes() if from_asymkey else b""
        dmail.destination_addr = addr
        dmail.subject = subject
        dmail.date = mutil.format_iso_datetime(date)

        if message_text:
            part = DmailPart()
            part.mime_type = "text/plain"
            part.data = message_text
            dmail.parts.append(part)

        dmail_bytes = dmail.encode()

        if from_asymkey:
            signature = from_asymkey.calc_rsassa_pss_sig(dmail_bytes)
            dmail_bytes += sshtype.encodeBinary(signature)

        storing_nodes = yield from\
            self._send_dmail(from_asymkey, rsite, dmail_bytes, signature)

        return storing_nodes

    @asyncio.coroutine
    def scan_dmail_address(self, addr, significant_bits, key_callback=None):
        if log.isEnabledFor(logging.INFO):
            log.info("Scanning dmail [{}].".format(mbase32.encode(addr)))

        def dbcall():
            with self.db.open_session() as sess:
                q = sess.query(db.DmailAddress)\
                    .filter(db.DmailAddress.site_key == addr)

                dmail_address = q.first()
                if dmail_address:
                    dmail_address.keys
                    sess.expunge_all()

                return dmail_address

        dmail_address = yield from self.loop.run_in_executor(None, dbcall)

        if dmail_address:
            log.info("Found DmailAddress locally, using local settings.")

            target = dmail_address.keys[0].target_key
            significant_bits = dmail_address.keys[0].difficulty
        else:
            log.info("DmailAddress not found locally, fetching settings from"\
                " the network.")

            addr, dsite = yield from\
                self.fetch_recipient_dmail_site(addr, significant_bits)

            if not dsite:
                raise DmailException("Dmail site not found.")

            target = dsite.root["target"]
            significant_bits = dsite.root["difficulty"]

            target = mbase32.decode(target)

        start = target

        while True:
            data_rw = yield from self.task_engine.send_find_key(\
                start, target_key=target, significant_bits=significant_bits,\
                retry_factor=100)

            key = data_rw.data_key

            if not key:
                break

            if log.isEnabledFor(logging.INFO):
                log.info("Found dmail key: [{}].".format(mbase32.encode(key)))

            if key_callback:
                key_callback(key)

            start = key

    @asyncio.coroutine
    def fetch_dmail(self, key, x=None, target_key=None):
        "Fetch the Dmail referred to by key from the network."\
        " Returns a Dmail object, not a db.DmailMessage object."

        data_rw = yield from self.task_engine.send_get_targeted_data(key)

        data = data_rw.data

        if not data:
            return None, None
        if not x:
            return data, None

        tb = mp.TargetedBlock(data)

        if target_key:
            if tb.target_key != target_key:
                tb_tid_enc = mbase32.encode(tb.target_key)
                tid_enc = mbase32.encode(target_key)
                raise DmailException(\
                    "TargetedBlock->target_key [{}] does not match request"\
                    " [{}]."\
                        .format(tb_tid_enc, tid_enc))

        version =\
            struct.unpack_from(">L", tb.buf, mp.TargetedBlock.BLOCK_OFFSET)[0]

        if version == 1:
            dmail, valid_sig =\
                yield from self._process_dmail_v1(key, x, tb, data_rw)
        else:
            assert version == 2
            dmail, valid_sig =\
                yield from self._process_dmail_v2(key, x, tb, data_rw)

        return dmail, valid_sig

    @asyncio.coroutine
    def _process_dmail_v1(self, key, x, tb, data_rw):
        dw = DmailWrapperV1(tb.buf, mp.TargetedBlock.BLOCK_OFFSET)

        if dw.ssm != "mdh-v1":
            raise DmailException(\
                "Unrecognized key exchange method in dmail [{}]."\
                    .format(dw.ssm))

        kex = dhgroup14.DhGroup14()
        kex.x = x
        kex.generate_e()
        kex.f = dw.ssf

        if dw.sse != kex.e:
            raise DmailException(\
                "Dmail [{}] is encrypted with a different e [{}] than"\
                " the specified x resulted in [{}]."\
                    .format(mbase32.encode(data_rw.data_key), dw.sse, kex.e))

        kex.calculate_k()

        key = self._generate_encryption_key(tb.target_key, kex.k)

        data = enc.decrypt_data_block(dw.data_enc, key)

        if not data:
            raise DmailException("Dmail data was empty.")

        dmail = DmailV1(data, 0, dw.data_len)

        if dw.signature:
            signature = dw.signature
            pubkey = rsakey.RsaKey(dmail.sender_pubkey)
            valid_sig = pubkey.verify_rsassa_pss_sig(dw.data_enc, signature)

            return dmail, valid_sig
        else:
            return dmail, False

    @asyncio.coroutine
    def _process_dmail_v2(self, key, x, tb, data_rw):
        dw = DmailWrapper(tb.buf, mp.TargetedBlock.BLOCK_OFFSET)

        if dw.ssm != "mdh-v1":
            raise DmailException(\
                "Unrecognized key exchange method in dmail [{}]."\
                    .format(dw.ssm))

        # Calculate the shared secret.
        kex = dhgroup14.DhGroup14()
        kex.x = x
        kex.generate_e()
        kex.f = dw.ssf

        if dw.sse != kex.e:
            raise DmailException(\
                "Dmail [{}] is encrypted with a different e [{}] than"\
                " the specified x resulted in [{}]."\
                    .format(mbase32.encode(data_rw.data_key), dw.sse, kex.e))

        kex.calculate_k()

        # Generate the AES-256 encryption key.
        key = self._generate_encryption_key(tb.target_key, kex.k)

        # Decrypt the data.
        data = enc.decrypt_data_block(dw.data_enc, key)

        if not data:
            raise DmailException("Dmail data was empty.")

        dmail = Dmail(data)

        if dmail.signature:
            pubkey = rsakey.RsaKey(dmail.sender_pubkey)
            valid_sig =\
                pubkey.verify_rsassa_pss_sig(\
                    data[:dmail.signature_offset], dmail.signature)

            return dmail, valid_sig
        else:
            return dmail, False

    def _generate_encryption_key(self, target_key, k):
        return enc.generate_ID(\
            b"The life forms running github are more retarded than any"\
            + b" retard!" + target_key + sshtype.encodeMpint(k)\
            + b"https://github.com/nixxquality/WebMConverter/commit/"\
            + b"c1ac0baac06fa7175677a4a1bf65860a84708d67")

    @asyncio.coroutine
    def _send_dmail(self, from_asymkey, recipient, dmail_bytes, signature):
        assert type(recipient) is DmailSite

        # Read in recipient DmailSite.
        root = recipient.root
        sse = sshtype.parseMpint(base58.decode(root["sse"]))[1]
        target_enc = root["target"]
        difficulty = root["difficulty"]

        # Calculate a shared secret.
        dh = dhgroup14.DhGroup14()
        dh.generate_x()
        dh.generate_e()
        dh.f = sse

        k = dh.calculate_k()

        target_key = mbase32.decode(target_enc)

        key = self._generate_encryption_key(target_key, k)

        # Encrypt the Dmail bytes.
        m, r = enc.encrypt_data_block(dmail_bytes, key)
        if m:
            if r:
                m = m + r
        else:
            m = r

        # Store it in a DmailWrapper.
        dw = DmailWrapper()
        dw.ssm = _dh_method_name
        dw.sse = sse
        dw.ssf = dh.e

        dw.data_len = len(dmail_bytes)
        dw.data_enc = m

        # Store the DmailWrapper in a TargetedBlock.
        tb = mp.TargetedBlock()
        tb.target_key = target_key
        tb.nonce = int(0).to_bytes(64, "big")
        tb.block = dw

        tb_data = tb.encode()
        tb_header = tb_data[:mp.TargetedBlock.BLOCK_OFFSET]

        # Do the POW on the TargetedBlock.
        if log.isEnabledFor(logging.INFO):
            log.info(\
                "Attempting work on dmail (target=[{}], difficulty=[{}])."\
                    .format(target_enc, difficulty))

        def threadcall():
            return brute.generate_targeted_block(\
                target_key, difficulty, tb_header,\
                mp.TargetedBlock.NOONCE_OFFSET,\
                mp.TargetedBlock.NOONCE_SIZE)

        nonce_bytes = yield from self.loop.run_in_executor(None, threadcall)

        if log.isEnabledFor(logging.INFO):
            log.info("Work found nonce [{}].".format(nonce_bytes))

        mp.TargetedBlock.set_nonce(tb_data, nonce_bytes)

        if log.isEnabledFor(logging.INFO):
            mp.TargetedBlock.set_nonce(tb_header, nonce_bytes)
            log.info("Message key=[{}]."\
                .format(mbase32.encode(enc.generate_ID(tb_header))))

        key = None

        def key_callback(val):
            nonlocal key
            key = val

        if log.isEnabledFor(logging.DEBUG):
            log.debug("TargetedBlock dump=[\n{}]."\
                .format(mutil.hex_dump(tb_data)))

        # Upload the TargetedBlock to the network.
        log.info("Sending dmail to the network.")

        total_storing = 0
        retry = 0
        while True:
            storing_nodes = yield from\
                self.task_engine.send_store_targeted_data(\
                    tb_data, store_key=True, key_callback=key_callback,\
                    retry_factor=retry * 10)

            total_storing += storing_nodes

            if total_storing >= 3:
                break

            if retry > 32:
                break
            elif retry > 3:
                yield from asyncio.sleep(1)

            retry += 1

        key_enc = mbase32.encode(key)
        id_enc = mbase32.encode(enc.generate_ID(key))

        if log.isEnabledFor(logging.INFO):
            log.info("Dmail sent; key=[{}], id=[{}], storing_nodes=[{}]."\
                .format(key_enc, id_enc, total_storing))

        return total_storing

    @asyncio.coroutine
    def fetch_recipient_dmail_site(self, addr, significant_bits=None):
        if type(addr) is str:
            addr, significant_bits = mutil.decode_key(addr)
        elif type(addr) in (list, tuple):
            addr, significant_bits = addr
        else:
            assert type(addr) in (bytes, bytearray)

        if significant_bits:
            data_rw = yield from self.task_engine.send_find_key(\
                addr, significant_bits=significant_bits)

            addr = bytes(data_rw.data_key)

            if not addr:
                log.info("Failed to find key for prefix [{}]."\
                    .format(recipient_enc))
                return None, None

        data_rw =\
            yield from self.task_engine.send_get_data(addr, retry_factor=100)

        if not data_rw.data:
            if log.isEnabledFor(logging.INFO):
                log.info("Failed to fetch dmail site [{}]."\
                    .format(mbase32.encode(recipient)))
            return None, None

        site_data = data_rw.data.decode("UTF-8")

        if log.isEnabledFor(logging.INFO):
            log.info("site_data=[{}].".format(site_data))

        return addr, DmailSite(site_data)

    @asyncio.coroutine
    def scan_and_save_new_dmails(self, dmail_address):
        assert type(dmail_address) is db.DmailAddress, type(dmail_address)

        new_dmail_cnt = 0
        old_dmail_cnt = 0
        err_dmail_cnt = 0

        address_key = dmail_address.keys[0]

        target = address_key.target_key
        significant_bits = address_key.difficulty

        start = target

        def check_have_dmail_dbcall():
            with self.db.open_session() as sess:
                q = sess.query(func.count("*")).select_from(db.DmailMessage)\
                    .filter(db.DmailMessage.data_key == dmail_key)

                if q.scalar():
                    return True
                return False

        while True:
            data_rw = yield from self.task_engine.send_find_key(\
                start, target_key=target, significant_bits=significant_bits,\
                retry_factor=100)

            start = dmail_key = data_rw.data_key

            if not dmail_key:
                if log.isEnabledFor(logging.INFO):
                    log.info("No more Dmails found for address (id=[{}])."\
                        .format(dmail_address.id))
                break

            if log.isEnabledFor(logging.INFO):
                key_enc = mbase32.encode(dmail_key)
                log.info("Found dmail key: [{}].".format(key_enc))

            exists =\
                yield from self.loop.run_in_executor(\
                    None, check_have_dmail_dbcall)

            if exists:
                if log.isEnabledFor(logging.DEBUG):
                    log.debug("Ignoring dmail (key=[{}]) we already have."\
                        .format(key_enc))
                    old_dmail_cnt += 1
                continue

            try:
                yield from self._fetch_and_save_dmail(\
                    dmail_key, dmail_address, address_key)
                new_dmail_cnt += 1
            except Exception as e:
                log.exception("Trying to fetch and save Dmail for key [{}]"\
                    " caused exception: {}"\
                        .format(mbase32.encode(dmail_key), e))
                err_dmail_cnt += 1

        if log.isEnabledFor(logging.INFO):
            if new_dmail_cnt:
                log.info("Moved [{}] Dmails to Inbox.".format(new_dmail_cnt))
            else:
                log.info("No new Dmails.")

        return new_dmail_cnt, old_dmail_cnt, err_dmail_cnt

    @asyncio.coroutine
    def _fetch_and_save_dmail(self, dmail_message_key, dmail_address,\
            address_key):
        key_type = type(dmail_message_key)
        if key_type is not bytes:
            assert key_type is bytearray
            dmail_message_key = bytes(dmail_message_key)

        # Fetch the Dmail data from the network.
        l, x_mpint = sshtype.parseMpint(address_key.x)
        dmobj, valid_sig =\
            yield from self.fetch_dmail(\
                dmail_message_key, x_mpint, address_key.target_key)

        if not dmobj:
            if log.isEnabledFor(logging.INFO):
                log.info("Dmail was not found on the network.")
            return False

        if dmobj.version > 1:
            if dmobj.destination_addr != dmail_address.site_key:
                log.warning(\
                    "Dmail was addressed to [{}], yet passed address was"\
                        " [{}]."\
                            .format(mbase32.encode(dmobj.destination_addr),\
                                mbase32.encode(dmail_address.site_key)))
                sig_valid = False

        # Save the Dmail to our local database.
        def dbcall():
            with self.db.open_session() as sess:
                self.db.lock_table(sess, db.DmailMessage)

                q = sess.query(func.count("*")).select_from(db.DmailMessage)\
                    .filter(db.DmailMessage.data_key == dmail_message_key)

                if q.scalar():
                    return False

                msg = db.DmailMessage()
                msg.dmail_address_id = dmail_address.id
                msg.dmail_key_id = address_key.id
                msg.data_key = dmail_message_key
                msg.sender_dmail_key =\
                    enc.generate_ID(dmobj.sender_pubkey)\
                        if dmobj.sender_pubkey else None
                msg.sender_valid = valid_sig
                msg.subject = dmobj.subject
                msg.date = mutil.parse_iso_datetime(dmobj.date)

                msg.hidden = False
                msg.read = False
                msg.deleted = False

                attach_dmail_tag(sess, msg, "Inbox")

                msg.parts = []

                for part in dmobj.parts:
                    dbpart = db.DmailPart()
                    dbpart.mime_type = part.mime_type
                    dbpart.data = part.data
                    msg.parts.append(dbpart)

                sess.add(msg)

                sess.commit()

        yield from self.loop.run_in_executor(None, dbcall)

        if log.isEnabledFor(logging.INFO):
            log.info("Dmail saved!")

        return True

def attach_dmail_tag(sess, dm, tag_name):
    "Make sure to call this in a separate thread than event loop."
    # Attach requested DmailTag to Dmail.
    q = sess.query(db.DmailTag)\
        .filter(db.DmailTag.name == tag_name)
    tag = q.first()

    if not tag:
        tag = db.DmailTag()
        tag.name = tag_name
        sess.add(tag)

    dm.tags.append(tag)
