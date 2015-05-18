#!/usr/bin/env python
# Written by Yu-Jie Lin
# Public Domain

from __future__ import print_function
import hashlib
import os
import sys
import timeit

# https://pypi.python.org/pypi/pysha3/
# sha3_* are introduced in Python 3.4+
if sys.version_info < (3, 4):
  import sha3

DATASIZE = 2**20
REPEAT = 3
NUMBER = 10
HASHES = (
  'md5',
  'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
  'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512',
)

width = max(len(f) for f in HASHES)

print(sys.version.replace('\n', ''))
print()

print('Generating random data %d...' % DATASIZE)
data = os.urandom(DATASIZE)

print('timeit for %d repeats, %d runs' % (REPEAT, NUMBER))
print()

for f in HASHES:
  t = timeit.Timer(
    '%s(data).hexdigest()' % f,
    'from __main__ import data; from hashlib import %s' % f
  )
  result = t.repeat(repeat=REPEAT, number=NUMBER)
  average = sum(result) / len(result)
  print('{:{width}s}: {:9.6f} seconds @ {:9.6f} MiB/s'.format(
    f,
    average,
    DATASIZE / average / (2**20),
    width=width
  ))
