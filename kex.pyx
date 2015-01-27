# This file is based upon parts from paramiko.
# LGPL               

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
        self.x = long(0)
        self.e = long(0)
        self.f = long(0)
        log.info("hi@#$")

    @asyncio.coroutine
    def test(self):
        print("TEST IS TEST")

    @asyncio.coroutine
    def start_kex(self):
        print("HI")
        self._generate_x()
        log.debug("x=[{}]".format(self.x))

        if self.protocol.server:
            # compute f = g^x mod p, but don't send it yet
            self.f = pow(self.G, self.x, self.P)
#            self.transport._expect_packet(_MSG_KEXDH_INIT)
            log.info("TEST")
            m = yield from self.protocol.read_packet()
            return self._parse_kexdh_reply(m)
        # compute e = g^x mod p (where g=2), and send it
        self.e = pow(self.G, self.x, self.P)
        m = mnetpacket.SshKexdhInitMessage()
        m.setE(self.e)
        m.encode()
        log.info("TEST2")
        self.protocol.write_packet(m)

#        self.transport._expect_packet(_MSG_KEXDH_REPLY)
        m = yield from self.protocol.read_packet()
#        return self._parse_kexdh_init(m)

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

    def _parse_kexdh_reply(self, m):
        # client mode
        host_key = m.get_string()
        self.f = m.get_mpint()
        if (self.f < 1) or (self.f > self.P - 1):
            raise SSHException('Server kex "f" is out of range')
        sig = m.get_binary()
        K = pow(self.f, self.x, self.P)
        # okay, build up the hash H of (V_C || V_S || I_C || I_S || K_S || e || f || K)
        hm = Message()
        hm.add(self.transport.local_version, self.transport.remote_version,
               self.transport.local_kex_init, self.transport.remote_kex_init)
        hm.add_string(host_key)
        hm.add_mpint(self.e)
        hm.add_mpint(self.f)
        hm.add_mpint(K)
        self.transport._set_K_H(K, sha1(hm.asbytes()).digest())
        self.transport._verify_key(host_key, sig)
        self.transport._activate_outbound()

    def _parse_kexdh_init(self, m):
        # server mode
        self.e = m.getE()
        if (self.e < 1) or (self.e > self.P - 1):
            raise SSHException('Client kex "e" is out of range')
        K = pow(self.e, self.x, self.P)
        key = self.protocol.get_server_key().asbytes()
        # okay, build up the hash H of (V_C || V_S || I_C || I_S || K_S || e || f || K)
        hm = bytearray()
        hm += sshtype.encodeString(self.protocol.getRemoteBanner())
        hm += sshtype.encodeString(self.protocol.getLocalBanner())
        hm += sshtype.encodeString(self.protocol.getRemoteKexInitMessage())
        hm += sshtype.encodeString(self.protocol.getLocalKexInitMessage())
        hm += sshtype.encodeString(key)
        hm += sshtype.encodeMpint(self.e)
        hm += sshtype.encodeMpint(self.f)
        hm += sshtype.encodeMpint(K)

        H = sha1(hm.asbytes()).digest()

        self.protocol.set_K_H(K, H)

        # sign it
        sig = self.transport.get_server_key().sign_ssh_data(H)
        # send reply
        m = Message()
        m.add_byte(c_MSG_KEXDH_REPLY)
        m.add_string(key)
        m.add_mpint(self.f)
        m.add_string(sig)
        self.transport._send_message(m)
        self.transport._activate_outbound()
