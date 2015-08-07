# Copyright (c) 2014-2015  Sam Maloney.
# License: LGPL

import llog

import asyncio
import logging
from hashlib import sha1

import dhgroup14
from sshexception import SshException
import sshtype
import packet as mnp

log = logging.getLogger(__name__)

class KexDhGroup14Sha1(object):
    name = "diffie-hellman-group14-sha1"

    def __init__(self, protocol):
        self.dh = dhgroup14.DhGroup14()

        self.protocol = protocol

    @asyncio.coroutine
    def run(self):
        dh = self.dh
        p = self.protocol
        server_mode = p.server_mode

        dh.generate_x()
        if log.isEnabledFor(logging.DEBUG):
            log.debug("x=[{}]".format(dh.x))

        dh.generate_e()
        if log.isEnabledFor(logging.DEBUG):
            log.debug("e=[{}]".format(dh.e))

        if server_mode:
            pkt = yield from p.read_packet()
            if not pkt:
                return False

            m = mnp.SshKexdhInitMessage(pkt)
            if log.isEnabledFor(logging.DEBUG):
                log.debug("Client sent e=[{}].".format(m.e))

            self._parse_kexdh_init(m)

            m = mnp.SshNewKeysMessage()
            m.encode()
            p.write_packet(m)

            return True

        # Client mode:
        m = mnp.SshKexdhInitMessage()
        m.e = dh.e
        m.encode()
        p.write_packet(m)

        pkt = yield from p.read_packet()
        if not pkt:
            return False

        m = mnp.SshKexdhReplyMessage(pkt)

        r = yield from self._parse_kexdh_reply(m)

        if not r:
            # Client signature failed OR the client sig was valid but the id
            # now verified is not wanted/allowed for connection.
            return False

        m = mnp.SshNewKeysMessage()
        m.encode()
        p.write_packet(m)

        # Signal successful authentication.
        return True

    @asyncio.coroutine
    def _parse_kexdh_reply(self, m):
        # The client runs this function.
        host_key = m.host_key

        server_f = self.dh.f = m.f

        if (server_f < 1) or (server_f > self.dh.P - 1):
            raise SshException('Server kex "f" is out of range')

        K = self.dh.calculate_k()

        if log.isEnabledFor(logging.DEBUG):
            log.debug("K=[{}].".format(K))

        # H = (V_C || V_S || I_C || I_S || K_S || e || f || K).
        hm = bytearray()
        hm += sshtype.encodeString(self.protocol.local_banner)
        hm += sshtype.encodeString(self.protocol.remote_banner)
        hm += sshtype.encodeBinary(self.protocol.local_kex_init_message)
        hm += sshtype.encodeBinary(self.protocol.remote_kex_init_message)
        hm += sshtype.encodeBinary(host_key)
        hm += sshtype.encodeMpint(self.dh.e)
        hm += sshtype.encodeMpint(server_f)
        hm += sshtype.encodeMpint(K)

        H = sha1(hm).digest()

        self.protocol.set_K_H(K, H)

        log.info("Verifying signature...")
        r = yield from self.protocol.verify_server_key(host_key, m.signature)
        return r

    def _parse_kexdh_init(self, m):
        # The server runs this function.
        client_e = self.dh.f = m.e

        if (client_e < 1) or (client_e > self.dh.P - 1):
            raise SshException("Client kex 'e' is out of range")

        K = self.dh.calculate_k()

        if log.isEnabledFor(logging.DEBUG):
            log.debug("K=[{}].".format(K))

        key = self.protocol.server_key.asbytes()

        # H = (V_C || V_S || I_C || I_S || K_S || e || f || K).
        hm = bytearray()
        hm += sshtype.encodeString(self.protocol.remote_banner)
        hm += sshtype.encodeString(self.protocol.local_banner)
        hm += sshtype.encodeBinary(self.protocol.remote_kex_init_message)
        hm += sshtype.encodeBinary(self.protocol.local_kex_init_message)
        hm += sshtype.encodeBinary(key)
        hm += sshtype.encodeMpint(client_e)
        hm += sshtype.encodeMpint(self.dh.e)
        hm += sshtype.encodeMpint(K)

        H = sha1(hm).digest()

        self.protocol.set_K_H(K, H)

        # Sign it.
        sig = self.protocol.server_key.sign_ssh_data(H)

        # Send reply.
        m = mnp.SshKexdhReplyMessage()
        m.host_key = key
        m.f = self.dh.e
        m.signature = sig
        m.encode()

        self.protocol.write_packet(m)
