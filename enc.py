# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

from hashlib import sha512
import os

from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA

# generate_ID outputs 512 bits.
ID_BITS = 512

def generate_RSA(bits=4096):
    '''
    Generate an RSA keypair with an exponent of 65537 in PEM format
    param: bits The key length in bits
    Return private key and public key
    '''

    new_key = RSA.generate(bits, e=65537)
    #public_key = new_key.publickey().exportKey("PEM")
    #private_key = new_key.exportKey("PEM")

    #return private_key, public_key 
    return new_key;

def generate_ID(data):
#    return SHA512.new(data).digest()
    return sha512(data).digest()

def _generate_ID(data):
    return SHA512.new(data)

def _setup_data_cipher(data_key):
    assert len(data_key) == 64, len(data_key)

    key = data_key[:32]
    iv = data_key[32:48]

    return AES.new(key, AES.MODE_CBC, iv)

def encrypt_data_block(data, data_key):
    cipher = _setup_data_cipher(data_key)

    data_len = len(data)
    remainder_len = data_len % 16
    main_len = data_len - remainder_len

    # Blasted pycrypto, does bytes(bytearray(...)) copy data? We Need a python
    # expert to go through the code and minimize or even hack fix all copying
    # of data.
    main_chunk = cipher.encrypt(bytes(data[:main_len]))
    if remainder_len:
        last_chunk = data[main_len:] + data_key[48:64 - remainder_len]
        remainder = cipher.encrypt(bytes(last_chunk))
    else:
        remainder = None

    return main_chunk, remainder

def decrypt_data_block(enc_data, data_key):
    cipher = _setup_data_cipher(data_key)

    data_len = len(enc_data)
    remainer_len = data_len % 16

    assert not remainer_len

    if type(enc_data) is bytearray:
        enc_data = bytes(enc_data) # Silly pycrypto.

    return cipher.decrypt(enc_data)
