# This file is based upon parts from paramiko (r85d5e95f9280aa236602b77e9f5bd0aa4d3c8fcd).
# LGPL

"""
RSA keys.
"""
import llog

import os
from hashlib import sha1
import logging

from Crypto.PublicKey import RSA

import putil as util
from putil import *

import sshtype
import asymkey
from sshexception import *

log = logging.getLogger(__name__)

SHA1_DIGESTINFO = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'

#class RsaKey (PKey):
class RsaKey(asymkey.AsymKey):
    """
    Representation of an RSA key which can be used to sign and verify SSH2
    data.
    """

    def __init__(self, data=None, filename=None, password=None, vals=None, file_obj=None):
        self.n = None
        self.e = None
        self.d = None
        self.p = None
        self.q = None
        if file_obj is not None:
            self._from_private_key(file_obj, password)
            return
        if filename is not None:
            self._from_private_key_file(filename, password)
            return
        if vals is not None:
            self.e, self.n = vals
        else:
            if data is None:
                raise SshException('Key object may not be empty')
            i, v = sshtype.parseString(data)
            if v != 'ssh-rsa':
                raise SshException('Invalid key')
            l, self.e = sshtype.parseMpint(data[i:])
            i += l
            l, self.n = sshtype.parseMpint(data[i:])
        self.size = util.bit_length(self.n)

    def asbytes(self):
        m = bytearray()
        m += sshtype.encodeString('ssh-rsa')
        m += sshtype.encodeMpint(self.e)
        m += sshtype.encodeMpint(self.n)
        return m

    def __str__(self):
        return self.asbytes()

    def __hash__(self):
        h = hash(self.get_name())
        h = h * 37 + hash(self.e)
        h = h * 37 + hash(self.n)
        return hash(h)

    def get_name(self):
        return 'ssh-rsa'

    def get_bits(self):
        return self.size

    def can_sign(self):
        return self.d is not None

    def sign_ssh_data(self, data):
        digest = sha1(data).digest()
        rsa = RSA.construct((int(self.n), int(self.e), int(self.d)))
        sig = util.deflate_long(rsa.sign(self._pkcs1imify(digest), bytes())[0], 0)
        m = bytearray()
        m += sshtype.encodeString('ssh-rsa')
        m += sshtype.encodeBinary(sig)
        return m

    def verify_ssh_sig(self, key_data, sig_msg):
        i, v = sshtype.parseString(sig_msg)
        if v != 'ssh-rsa':
            log.warning("Not an ssh-rsa signature!")
            return False
        log.info("l[{}][{}]".format(i, len(sig_msg)))
        sig = util.inflate_long(sshtype.parseBinary(sig_msg[i:])[1], True)
        # verify the signature by SHA'ing the key_data and encrypting it using the
        # public key.  some wackiness ensues where we "pkcs1imify" the 20-byte
        # hash into a string as long as the RSA key.
        log.info("sig=[{}].".format(sig))
        hash_obj = util.inflate_long(self._pkcs1imify(sha1(key_data).digest()), True)
        rsa = RSA.construct((int(self.n), int(self.e)))
        return rsa.verify(hash_obj, (sig, ))

    def _encode_key(self):
        if (self.p is None) or (self.q is None):
            raise SshException('Not enough key info to write private key file')
        """
        keylist = [0, self.n, self.e, self.d, self.p, self.q,
                   self.d % (self.p - 1), self.d % (self.q - 1),
                   util.mod_inverse(self.q, self.p)]
        try:
            b = BER()
            b.encode(keylist)
        except BERException:
            raise SshException('Unable to create ber encoding of key')
        return b.asbytes()
        """
        b = bytearray()

        b += struct.pack("B", 1) # mnk version.
        b += sshtype.encodeMpint(self.e)
        b += sshtype.encodeMpint(self.n)
        b += sshtype.encodeMpint(self.d)
        b += sshtype.encodeMpint(self.p)
        b += sshtype.encodeMpint(self.q)

        return b

    def write_private_key_file(self, filename, password=None):
        self._write_private_key_file('RSA', filename, self._encode_key(), password)

    def write_private_key(self, file_obj, password=None):
        self._write_private_key('RSA', file_obj, self._encode_key(), password)

    @staticmethod
    def generate(bits, progress_func=None):
        """
        Generate a new private RSA key.  This factory function can be used to
        generate a new host key or authentication key.

        :param int bits: number of bits the generated key should be.
        :param function progress_func:
            an optional function to call at key points in key generation (used
            by ``pyCrypto.PublicKey``).
        :return: new `.RsaKey` private key
        """
        rsa = RSA.generate(bits, os.urandom, progress_func)
        key = RsaKey(vals=(rsa.e, rsa.n))
        key.d = rsa.d
        key.p = rsa.p
        key.q = rsa.q
        return key

    ###  internals...

    def _pkcs1imify(self, data):
        """
        turn a 20-byte SHA1 hash into a blob of data as large as the key's N,
        using PKCS1's \"emsa-pkcs1-v1_5\" encoding.  totally bizarre.
        """
        size = len(util.deflate_long(self.n, 0))
        filler = max_byte * (size - len(SHA1_DIGESTINFO) - len(data) - 3)
        return zero_byte + one_byte + filler + zero_byte + SHA1_DIGESTINFO + data

    def _from_private_key_file(self, filename, password):
        data = self._read_private_key_file('RSA', filename, password)
        self._decode_key(data)

    def _from_private_key(self, file_obj, password):
        data = self._read_private_key('RSA', file_obj, password)
        self._decode_key(data)

    def _decode_key(self, data):
        """
        # private key file contains:
        # RSAPrivateKey = { version = 0, n, e, d, p, q, d mod p-1, d mod q-1, q**-1 mod p }
        try:
            keylist = BER(data).decode()
        except BERException:
            raise SshException('Unable to parse key file')
        if (type(keylist) is not list) or (len(keylist) < 4) or (keylist[0] != 0):
            raise SshException('Not a valid RSA private key file (bad ber encoding)')
        self.n = keylist[1]
        self.e = keylist[2]
        self.d = keylist[3]
        # not really needed
        self.p = keylist[4]
        self.q = keylist[5]
        self.size = util.bit_length(self.n)
        """

        ver = struct.unpack("B", data[:1])[0]
        if ver != 1:
            raise SshException("Unsupported mnk version [{}].".format(ver))
        i = 1
        l, self.e = sshtype.parseMpint(data[i:])
        i += l
        l, self.n = sshtype.parseMpint(data[i:])
        i += l
        l, self.d = sshtype.parseMpint(data[i:])
        i += l
        l, self.p = sshtype.parseMpint(data[i:])
        i += l
        l, self.q = sshtype.parseMpint(data[i:])
