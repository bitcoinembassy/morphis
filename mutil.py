# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

from bisect import bisect_left
from datetime import datetime, tzinfo, timedelta
import logging
import time

import consts
import mbase32

log = logging.getLogger(__name__)

accept_chars = b" !\"#$%&`()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_'abcdefghijklmnopqrstuvwxyz{|}~"
accept_chars = sorted(accept_chars)

width = 16

def hex_dump(data, offset = 0, length = None):
    assert type(data) in (bytes, bytearray), type(data)

    output = bytearray()
    col1 = bytearray()
    col2 = bytearray()

    if length == None:
        length = len(data)

    line = 0
    i = offset
    while i < length:
        j = 0
        while j < width and i < length:
            val = data[i]
            col1 += format(val, "02x").encode()

            si = bisect_left(accept_chars, data[i])
            if si != len(accept_chars) and accept_chars[si] == data[i]:
                col2.append(data[i])
            else:
                col2 += b'.'

            if j % 2 == 1:
                col1 += b' '

            j += 1
            i += 1

        output += format(line * width, "#06x").encode()
        output += b"   "
        line += 1
        while len(col1) < (width*5/2):
            col1 += b' '

        output += col1
        output += b' '
        output += col2
        output += b'\n'
        col1.clear()
        col2.clear()

    return output.decode()

bc_masks = [0x2, 0xC, 0xF0]
bc_shifts = [1, 2, 4]

def log_base2_8bit(val):
    r = 0

    for i in range(2, -1, -1):
        if val & bc_masks[i]:
            val >>= bc_shifts[i]
            r |= bc_shifts[i]

    return r

def hex_string(val):
    if not val:
        return None

    buf = ""

    for b in val:
        if b <= 0x0F:
            buf += '0'
        buf += hex(b)[2:]

    return buf

#TODO: Maybe move this to db.py and make it use cursor if in PostgreSQL mode.
def page_query(query, page_size=10):
    "Batch fetch an SQLAlchemy query."

    offset = 0

    while True:
        page = query.limit(page_size).offset(offset).all()

        for row in page:
            yield row

        if len(page) < page_size:
            break

        offset += page_size

def decode_key(encoded):
    assert consts.NODE_ID_BITS == 512
    assert type(encoded) is str, type(encoded)

    significant_bits = None

    kl = len(encoded)

    if kl == 128:
        data_key = bytes.fromhex(encoded)
    elif kl in (102, 103):
        data_key = bytes(mbase32.decode(encoded))
        if len(data_key) < consts.NODE_ID_BYTES:
            significant_bits = 5 * kl
    else:
        data_key = mbase32.decode(encoded, False)
        significant_bits = 5 * kl

    return data_key, significant_bits

def calc_raw_distance(data1, data2):
    "Calculates the XOR distance, return is absolute value."

    assert type(data1) in (bytes, bytearray)\
        and type(data2) in (bytes, bytearray)

    buf = bytearray()

    for i in range(len(data1)):
        buf.append(data1[i] ^ data2[i])

    return buf

def calc_log_distance(nid, pid):
    "Returns: distance, direction."
    " distance is in log base2."

    id_size = len(nid)
    assert id_size >= len(pid)

    if log.isEnabledFor(logging.DEBUG):
        log.debug("pid=\n[{}], nid=\n[{}].".format(hex_dump(pid),\
            hex_dump(nid)))

    dist = 0
    direction = 0

    for i in range(id_size):
        if pid[i] != nid[i]:
            direction = 1 if pid[i] > nid[i] else -1

            xv = pid[i] ^ nid[i]
            xv = log_base2_8bit(xv) + 1

            # (byte * 8) + bit.
            dist = ((id_size - 1 - i) << 3) + xv

            break

    return dist, direction

ZERO_TIMEDELTA = timedelta(0)
class UtcTzInfo(tzinfo):
    def utcoffset(self, dt):
        return ZERO_TIMEDELTA

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return ZERO_TIMEDELTA

UTC_TZINFO = UtcTzInfo()

def utc_datetime():
    return datetime.now(UTC_TZINFO)

ISO_FMT_UTC = "%Y-%m-%dT%H:%M:%S.%fZ"
ISO_FMT = "%Y-%m-%dT%H:%M:%S.%f"

def parse_iso_datetime(date_str):
    if date_str.endswith('Z'):
        return datetime.strptime(date_str, ISO_FMT_UTC)\
            .replace(tzinfo=UTC_TZINFO)
    else:
        return datetime.strptime(date_str, ISO_FMT)

def format_iso_datetime(adatetime):
    if adatetime.tzinfo is UTC_TZINFO:
        return adatetime.strftime(ISO_FMT_UTC)
    else:
        return adatetime.strftime(ISO_FMT)

iso_fmt_human_no_ms = "%Y-%m-%d %H:%M:%S"

def get_utc_offset_seconds():
    return time.altzone if time.daylight else time.timezone

def format_human_no_ms_datetime(datetime, convert_local=True, assume_gmt=False):
    if convert_local and (assume_gmt or datetime.tzinfo is UTC_TZINFO):
        datetime = datetime - timedelta(seconds=get_utc_offset_seconds())
    return datetime.strftime(iso_fmt_human_no_ms)
