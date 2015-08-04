# Copyright (C) 2011 Sam Rushing.
# Copyright (C) 2013-2014 The python-bitcoinlib developers.
# License: LGPL.
#
# This file is based upon parts from python-bitcoinlib (e3cdf68eaff2fc7cbcd10a488e0485e0b694f806).

"""Base58 encoding and decoding"""

from __future__ import absolute_import, division, print_function, unicode_literals

import sys
_bchr = chr
_bord = ord
if sys.version > '3':
    long = int
    _bchr = lambda x: bytes([x])
    _bord = lambda x: x

import binascii

#import bitcoin.core

B58_DIGITS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

class Base58Error(Exception):
    pass

class InvalidBase58Error(Base58Error):
    """Raised on generic invalid base58 data, such as bad characters.
    Checksum failures raise Base58ChecksumError specifically.
    """
    pass

def encode(b):
    """Encode bytes to a base58-encoded string"""

    # Convert big-endian bytes to integer
    n = int('0x0' + binascii.hexlify(b).decode('utf8'), 16)

    # Divide that integer into bas58
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(B58_DIGITS[r])
    res = ''.join(res[::-1])

    # Encode leading zeros as base58 zeros
    czero = b'\x00'
    if sys.version > '3':
        # In Python3 indexing a bytes returns numbers, not characters.
        czero = 0
    pad = 0
    for c in b:
        if c == czero:
            pad += 1
        else:
            break
    return B58_DIGITS[0] * pad + res

def decode(s):
    """Decode a base58-encoding string, returning bytes"""
    if not s:
        return b''

    # Convert the string to an integer
    n = 0
    for c in s:
        n *= 58
        if c not in B58_DIGITS:
            raise InvalidBase58Error(\
                "Character %r is not a valid base58 character" % c)
        digit = B58_DIGITS.index(c)
        n += digit

    # Convert the integer to bytes
    h = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = binascii.unhexlify(h.encode('utf8'))

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == B58_DIGITS[0]: pad += 1
        else: break
    return b'\x00' * pad + res
