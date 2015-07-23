# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>.
# Copyright (C) 2014-2015  Sam Maloney.
# License: LGPL.
#
# This file is based upon parts from paramiko (r85d5e95f9280aa236602b77e9f5bd0aa4d3c8fcd).

"""
DSS keys.
"""

import os
from hashlib import sha1

from Crypto.PublicKey import DSA

import putil as util
from putil import *

import sshtype

#class DssKey (PKey):
class DssKey():
    """
    Representation of a DSS key which can be used to sign an verify SSH2
    data.
    """

    def __init__(self, msg=None, data=None, filename=None, password=None, vals=None, file_obj=None):
        self.p = None
        self.q = None
        self.g = None
        self.y = None
        self.x = None
        if file_obj is not None:
            self._from_private_key(file_obj, password)
            return
        if filename is not None:
            self._from_private_key_file(filename, password)
            return
        if (msg is None) and (data is not None):
            msg = Message(data)
        if vals is not None:
            self.p, self.q, self.g, self.y = vals
        else:
            if msg is None:
                raise SSHException('Key object may not be empty')
            if msg.get_text() != 'ssh-dss':
                raise SSHException('Invalid key')
            self.p = msg.get_mpint()
            self.q = msg.get_mpint()
            self.g = msg.get_mpint()
            self.y = msg.get_mpint()
        self.size = util.bit_length(self.p)

    def asbytes(self):
        m = bytearray()
        m += sshtype.encodeString('ssh-dss')
        m += sshtype.encodeMpint(self.p)
        m += sshtype.encodeMpint(self.q)
        m += sshtype.encodeMpint(self.g)
        m += sshtype.encodeMpint(self.y)
        return m

    def __str__(self):
        return self.asbytes()

    def __hash__(self):
        h = hash(self.get_name())
        h = h * 37 + hash(self.p)
        h = h * 37 + hash(self.q)
        h = h * 37 + hash(self.g)
        h = h * 37 + hash(self.y)
        # h might be a long by now...
        return hash(h)

    def get_name(self):
        return 'ssh-dss'

    def get_bits(self):
        return self.size

    def can_sign(self):
        return self.x is not None

    def sign_ssh_data(self, data):
        digest = sha1(data).digest()
        dss = DSA.construct((int(self.y), int(self.g), int(self.p), int(self.q), int(self.x)))
        # generate a suitable k
        qsize = len(util.deflate_long(self.q, 0))
        while True:
            k = util.inflate_long(os.urandom(qsize), 1)
            if (k > 2) and (k < self.q):
                break
        r, s = dss.sign(util.inflate_long(digest, 1), k)
        m = bytearray()
        m += sshtype.encodeString("ssh-dss")
        # apparently, in rare cases, r or s may be shorter than 20 bytes!
        rstr = util.deflate_long(r, 0)
        sstr = util.deflate_long(s, 0)
        if len(rstr) < 20:
            rstr = zero_byte * (20 - len(rstr)) + rstr
        if len(sstr) < 20:
            sstr = zero_byte * (20 - len(sstr)) + sstr
        m += sshtype.encodeBinary(rstr + sstr)
        return m

    def verify_ssh_sig(self, data, msg):
        if len(msg.asbytes()) == 40:
            # spies.com bug: signature has no header
            sig = msg.asbytes()
        else:
            kind = msg.get_text()
            if kind != 'ssh-dss':
                return 0
            sig = msg.get_binary()

        # pull out (r, s) which are NOT encoded as mpints
        sigR = util.inflate_long(sig[:20], 1)
        sigS = util.inflate_long(sig[20:], 1)
        sigM = util.inflate_long(sha1(data).digest(), 1)

        dss = DSA.construct((int(self.y), int(self.g), int(self.p), int(self.q)))
        return dss.verify(sigM, (sigR, sigS))

    def _encode_key(self):
        if self.x is None:
            raise SSHException('Not enough key information')
        keylist = [0, self.p, self.q, self.g, self.y, self.x]
        try:
            b = BER()
            b.encode(keylist)
        except BERException:
            raise SSHException('Unable to create ber encoding of key')
        return b.asbytes()

    def write_private_key_file(self, filename, password=None):
        self._write_private_key_file('DSA', filename, self._encode_key(), password)

    def write_private_key(self, file_obj, password=None):
        self._write_private_key('DSA', file_obj, self._encode_key(), password)

    @staticmethod
    def generate(bits=1024, progress_func=None):
        """
        Generate a new private DSS key.  This factory function can be used to
        generate a new host key or authentication key.

        :param int bits: number of bits the generated key should be.
        :param function progress_func:
            an optional function to call at key points in key generation (used
            by ``pyCrypto.PublicKey``).
        :return: new `.DssKey` private key
        """
        dsa = DSA.generate(bits, os.urandom, progress_func)
        key = DssKey(vals=(dsa.p, dsa.q, dsa.g, dsa.y))
        key.x = dsa.x
        return key

    ###  internals...

    def _from_private_key_file(self, filename, password):
        data = self._read_private_key_file('DSA', filename, password)
        self._decode_key(data)

    def _from_private_key(self, file_obj, password):
        data = self._read_private_key('DSA', file_obj, password)
        self._decode_key(data)

    def _decode_key(self, data):
        # private key file contains:
        # DSAPrivateKey = { version = 0, p, q, g, y, x }
        try:
            keylist = BER(data).decode()
        except BERException as e:
            raise SSHException('Unable to parse key file: ' + str(e))
        if (type(keylist) is not list) or (len(keylist) < 6) or (keylist[0] != 0):
            raise SSHException('not a valid DSA private key file (bad ber encoding)')
        self.p = keylist[1]
        self.q = keylist[2]
        self.g = keylist[3]
        self.y = keylist[4]
        self.x = keylist[5]
        self.size = util.bit_length(self.p)
