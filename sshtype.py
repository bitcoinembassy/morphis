import struct
import logging

import llog
import putil

log = logging.getLogger(__name__)

def parseNameList(buf):
    return parseString(buf)

def parse_string_from(buf, i):
    length = struct.unpack_from(">L", buf, i)[0]

    if log.isEnabledFor(logging.DEBUG):
        log.debug("length={}".format(length))

    start = i + 4
    value = buf[start:start + length].decode()

    return length + 4, value

def parseString(buf):
    length = struct.unpack(">L", buf[0:4])[0]
    if log.isEnabledFor(logging.DEBUG):
        log.debug("length={}".format(length))
    value = buf[4:4 + length].decode()

    return length + 4, value

def parseBinary(buf):
    length = struct.unpack(">L", buf[0:4])[0]
    if log.isEnabledFor(logging.DEBUG):
        log.debug("length={}".format(length))
    value = buf[4:4 + length]

    return length + 4, value

def parseMpint(buf):
    length = struct.unpack(">L", buf[0:4])[0]
    if log.isEnabledFor(logging.DEBUG):
        log.debug("length={}".format(length))
    return length + 4, putil.inflate_long(buf[4:4+length])

def encodeMpint(val):
    buf = putil.deflate_long(val)
    length = struct.pack(">L", len(buf))
    return length + buf

def encodeNameList(val):
    return encodeString(val)

def encodeString(val):
#    if log.isEnabledFor(logging.DEBUG):
#        log.debug("type=[{}].".format(type(val)))
#    if isinstance(val, bytes) or isinstance(val, bytearray):
#        buf = val
#    else:
    buf = val.encode(encoding="UTF-8")

    length = struct.pack(">L", len(buf))
    return length + buf

def encodeBinary(buf):
    length = struct.pack(">L", len(buf))
    return length + buf
