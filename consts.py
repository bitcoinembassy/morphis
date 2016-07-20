# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

from enum import Enum

import enc

NODE_ID_BITS = enc.ID_BITS
NODE_ID_BYTES = NODE_ID_BITS >> 3
MAX_DATA_BLOCK_SIZE = 32768

NULL_KEY = bytes([0x00] * NODE_ID_BYTES)
NULL_LONG = bytes((0x00,) * 4)

NSK_DEFAULT_ADDRESS = "default_address"
NSK_SCHEMA_VERSION = "schema_version"

class BlockType(Enum):
    hash_tree = 0x2D4100
    link = 0x2D4200
    targeted = 0x2D4300
    user = 0x80000000

