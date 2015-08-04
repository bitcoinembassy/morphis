# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>.
# Copyright (C) 2014-2015  Sam Maloney.
# License: LGPL.
#
# This file is based upon parts from paramiko (r85d5e95f9280aa236602b77e9f5bd0aa4d3c8fcd).

import llog

import os
import asyncio
import logging
from hashlib import sha1

from putil import *
import putil

import sshtype
import packet as mnetpacket

"""
Standard SSH key exchange ("kex" if you wanna sound cool).  Diffie-Hellman of
2048 bit key halves, using a known "p" prime and "g" generator.
"""

log = logging.getLogger(__name__)

_MSG_KEXDH_INIT, _MSG_KEXDH_REPLY = range(30, 32)
c_MSG_KEXDH_INIT, c_MSG_KEXDH_REPLY = [byte_chr(c) for c in range(30, 32)]

b7fffffffffffffff = byte_chr(0x7f) + max_byte * 7
b0000000000000000 = zero_byte * 8

class KexGroup14():

    # http://tools.ietf.org/html/rfc3526#section-3
    P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    G = 2

    name = 'diffie-hellman-group14-sha1'

    def __init__(self, protocol):
        self.protocol = protocol
        self.x = int(0)
        self.e = int(0)
        self.f = int(0)

    @asyncio.coroutine
    def do_kex(self):
        # This method can return False for client mode if the client,
        # after successfull authentication, is rejected by its id.

        self._generate_x()

        if log.isEnabledFor(logging.DEBUG):
            log.debug("x=[{}]".format(self.x))

        if self.protocol.server_mode:
            # compute f = g^x mod p, but don't send it yet
            self.f = pow(self.G, self.x, self.P)
#            self.transport._expect_packet(_MSG_KEXDH_INIT)

            pkt = yield from self.protocol.read_packet()
            if not pkt:
                return False
            m = mnetpacket.SshKexdhInitMessage(pkt)
            if log.isEnabledFor(logging.DEBUG):
                log.debug("Client sent e=[{}].".format(m.e))
            self._parse_kexdh_init(m)

#            pkt = yield from self.protocol.read_packet()
#            m = mnetpacket.SshNewKeysMessage(pkt)
#            log.debug("Received SSH_MSG_NEWKEYS.")

            m = mnetpacket.SshNewKeysMessage()
            m.encode()
            self.protocol.write_packet(m)
            return True

        # compute e = g^x mod p (where g=2), and send it
        self.e = pow(self.G, self.x, self.P)
        if log.isEnabledFor(logging.DEBUG):
            log.debug("Sending e=[{}].".format(self.e))
        m = mnetpacket.SshKexdhInitMessage()
        m.e = self.e
        m.encode()
        self.protocol.write_packet(m)

#        self.transport._expect_packet(_MSG_KEXDH_REPLY)
        pkt = yield from self.protocol.read_packet()
        if not pkt:
            return False
        m = mnetpacket.SshKexdhReplyMessage(pkt)

        r = yield from self._parse_kexdh_reply(m)

        if not r:
            # Client is rejected for some reason by higher level.
            return False

        m = mnetpacket.SshNewKeysMessage()
        m.encode()
        self.protocol.write_packet(m)

#        pkt = yield from self.protocol.read_packet()
#        m = mnetpacket.SshNewKeysMessage(pkt)
#        log.debug("Received SSH_MSG_NEWKEYS.")

        return True

    ###  internals...

    def _generate_x(self):
        # generate an "x" (1 < x < q), where q is (p-1)/2.
        # p is a 256-byte (2048-bit) number, where the first ?? bits are 1. 
        # therefore ?? q can be approximated as a 2^2047.  we drop the subset of
        # potential x where the first 63 bits are 1, because some of those will be
        # larger than q (but this is a tiny tiny subset of potential x).
        while 1:
            x_bytes = os.urandom(256)
            x_bytes = byte_mask(x_bytes[0], 0x7f) + x_bytes[1:]
            if (x_bytes[:8] != b7fffffffffffffff and
                    x_bytes[:8] != b0000000000000000):
                break
        self.x = putil.inflate_long(x_bytes)

    @asyncio.coroutine
    def _parse_kexdh_reply(self, m):
        # client mode
        host_key = m.host_key
        self.f = m.f
        if (self.f < 1) or (self.f > self.P - 1):
            raise SshException('Server kex "f" is out of range')
        sig = m.signature
        K = pow(self.f, self.x, self.P)
        if log.isEnabledFor(logging.DEBUG):
            log.debug("K=[{}].".format(K))
        # okay, build up the hash H of (V_C || V_S || I_C || I_S || K_S || e || f || K)
        hm = bytearray()
        hm += sshtype.encodeString(self.protocol.local_banner)
        hm += sshtype.encodeString(self.protocol.remote_banner)
        hm += sshtype.encodeBinary(self.protocol.local_kex_init_message)
        hm += sshtype.encodeBinary(self.protocol.remote_kex_init_message)
        hm += sshtype.encodeBinary(host_key)
        hm += sshtype.encodeMpint(self.e)
        hm += sshtype.encodeMpint(self.f)
        hm += sshtype.encodeMpint(K)

        H = sha1(hm).digest()

        self.protocol.set_K_H(K, H)

        log.info("Verifying signature...")
        r = yield from self.protocol.verify_server_key(host_key, sig)
        return r
#        self.transport._activate_outbound()

    def _parse_kexdh_init(self, m):
        # server mode
        self.e = m.e
        if (self.e < 1) or (self.e > self.P - 1):
            raise SshException('Client kex "e" is out of range')
        K = pow(self.e, self.x, self.P)
        if log.isEnabledFor(logging.DEBUG):
            log.debug("K=[{}].".format(K))
        key = self.protocol.server_key.asbytes()
        # okay, build up the hash H of (V_C || V_S || I_C || I_S || K_S || e || f || K)
        hm = bytearray()
        hm += sshtype.encodeString(self.protocol.remote_banner)
        hm += sshtype.encodeString(self.protocol.local_banner)
        hm += sshtype.encodeBinary(self.protocol.remote_kex_init_message)
        hm += sshtype.encodeBinary(self.protocol.local_kex_init_message)
        hm += sshtype.encodeBinary(key)
        hm += sshtype.encodeMpint(self.e)
        hm += sshtype.encodeMpint(self.f)
        hm += sshtype.encodeMpint(K)

        H = sha1(hm).digest()

        self.protocol.set_K_H(K, H)

        # sign it
        sig = self.protocol.server_key.sign_ssh_data(H)
        # send reply
        m = mnetpacket.SshKexdhReplyMessage()
        m.host_key = key
        m.f = self.f
        m.signature = sig
        m.encode()

        self.protocol.write_packet(m)
#        self.transport._activate_outbound()
