# Copyright (c) 2014-2015  Sam Maloney.
# License: GPL v2.

import llog

import logging

log = logging.getLogger(__name__)

none_found = object()

class BitTrie(object):
    def __init__(self):
        self.trie = [None] * 0x10

    def get(self, key, default=None):
        r = self._get(key)
        if r:
            return r
        return default

    def __setitem__(self, key, value):
        self.put(key, value)

    def __getitem__(self, key):
        r = self.get(key)
        if not r:
            raise KeyError()
        return r

    def __str__(self):
        buf = "["
        first = True

        for x in self.find(ZeroKey()):
            if not x:
                continue
            if not first:
                buf += ", "
            else:
                first = False
            buf += str(x)

        buf += "]"

        return buf

    def __iter__(self):
        for item in self.find(ZeroKey()):
            if item is none_found:
                continue
            yield item

    def __delitem__(self, key):
        self._del(key)

    default_default = object()

    def pop(self, key, default=default_default):
        r = self._del(key)

        if r:
            return r

        if default is not self.default_default:
            return default

        raise KeyError()

    def setdefault(self, key, default):
        r = self.put(key, default, False)
        if not r:
            return default
        return r

    def put(self, key, value, replace=True):
        node = self.trie

        keylen = len(key)
        for i in range(keylen):
            char = key[i]
            for j in range(4, -1, -4):
                bit = (char >> j) & 0x0F
                next_node = node[bit]

                if not next_node:
                    node[bit] = TrieLeaf(key, value)
                    return None

                if type(next_node) is TrieLeaf:
                    other = next_node

                    o_key = other.key
                    if j == 0:
                        ii = i + 1
                        if ii == keylen:
                            if replace:
                                node[bit] = TrieLeaf(key, value)
                            return other.value

                        next_o_bit = (o_key[ii] >> 4) & 0x0F
                    else:
                        next_o_bit = (o_key[i] >> (j-4)) & 0x0F

                    next_node = [None] * 0x10
                    next_node[next_o_bit] = other

                    node[bit] = next_node
                    node = next_node
                    continue

                assert type(next_node) is list, type(next_node)
                node = next_node

    def _del(self, key):
        #FIXME: Make this code prune empty trees more than one deep.
        prev_node = None
        prev_node_bit = None
        node = self.trie

        for i in range(len(key)):
            char = key[i]
            for j in range(4, -1, -4):
                bit = (char >> j) & 0x0F
                next_node = node[bit]

                if not next_node:
                    return None

                if type(next_node) is TrieLeaf:
                    node[bit] = None

                    empty = True
                    for n in node:
                        if n:
                            empty = False
                            break;

                    if empty and prev_node:
                        prev_node[prev_node_bit] = None

                    return next_node.value

                assert type(next_node) is list, type(next_node)

                prev_node = node
                prev_node_bit = bit
                node = next_node

    def _get(self, key):
        node = self.trie

        for i in range(len(key)):
            char = key[i]
            for j in range(4, -1, -4):
                bit = (char >> j) & 0x0F
                next_node = node[bit]

                if not next_node:
                    return None

                if type(next_node) is TrieLeaf:
                    if next_node.key == key:
                        return next_node.value
                    else:
                        return None

                assert type(next_node) is list, type(next_node)

                node = next_node

    def find(self, key, forward=True):
        "Generator. First element can be None sometimes when no exact match."
        branches = []
        node = self.trie

        key_len = len(key)
        i = 0
        while i < key_len:
            char = key[i]
            j = 4
            while j >= 0:
                bit = (char >> j) & 0x0F

                rng = range(0x0F, bit, -1) if forward else range(0, bit)

                for obit in rng:
                    other = node[obit]
                    if other:
                        branches.append(other)

                next_node = node[bit]

                if not next_node:
                    yield none_found

                    func = self._iterate_next(branches) if forward\
                        else self._iterate_prev(branches)

                    for r in func:
                        yield r
                    return None

                if type(next_node) is TrieLeaf:
                    nnk = next_node.key
                    kl = min(len(nnk), key_len)
                    while True:
                        if nnk[i] != key[i]:
                            greater = nnk[i] > key[i]

                            yield none_found

                            if greater ^ (not forward):
                                yield next_node.value

                            break

                        i = i + 1
                        if i == kl:
                            yield next_node.value
                            break

                    func = self._iterate_next(branches) if forward\
                        else self._iterate_prev(branches)

                    for r in func:
                        yield r

                    return None

                assert type(next_node) is list, type(next_node)

                node = next_node
                j = j - 4

            i = i + 1

    def _iterate_next(self, branches):
        while True:
            if not branches:
                return None

            node = branches.pop()

            if type(node) is TrieLeaf:
                yield node.value
                continue

            assert type(node) is list, type(node)

            branches.extend(reversed([x for x in node if x]))

    def _iterate_prev(self, branches):
        while True:
            if not branches:
                return None

            node = branches.pop()

            if type(node) is TrieLeaf:
                yield node.value
                continue

            assert type(node) is list, type(node)

            branches.extend([x for x in node if x])

class TrieLeaf(object):
    def __init__(self, key, value):
        self.key = key
        self.value = value

class XorKey(object):
    def __init__(self, key1, key2):
        self.key1 = key1
        self.key2 = key2

    def __getitem__(self, idx):
        return self.key1[idx] ^ self.key2[idx]

    def __len__(self):
        return len(self.key1)

max_len_value = 0xFFFFFFFF

class __TestLenObj(object):
    def __init__(self, length):
        self.length = max_len_value

    def __len__(self):
        return self.length

try:
    __test_len_obj = __TestLenObj(max_len_value)
    __test_len_r = len(__test_len_obj)
except OverflowError:
    log.info("Setting max_len_value to 0xFFFF.")
    max_len_value = 0xFFFF

class ZeroKey(object):
    def __init__(self, length=max_len_value):
        self.length = length

    def __getitem__(self, idx):
        return 0x00

    def __len__(self):
        return self.length

    def __eq__(self, other):
        return other.length == self.length

import random
import os
from datetime import datetime

def _del_test():
    print("del..")

    bt = BitTrie()

    dels = []

    for i in range(10):
        ri = random.randint(0, 100)
        k = ri.to_bytes(1, "big")

        r = bt[k] = ri

        if i % 3:
            print("DEL: {}".format(ri))
            dels.append(k)

    print(bt)

    for del_ in dels:
        del bt[del_]

    print(bt)

def _speed_test():
    bt = BitTrie()
#    bt = {}

    rval = os.urandom(512>>3)

    for i in range(500000):
        val = os.urandom(512>>3)

        xval = [rvalc ^ valc for rvalc, valc in zip(rval, val)]
        xiv = int.from_bytes(xval, "big")

        k = XorKey(rval, val)

        now = datetime.today()
        #r = bt.put(k, xiv)
        r = bt[k] = xiv
        if not i % 5000:
            print("put took: {}".format(datetime.today() - now))

    n = XorKey(os.urandom(512>>3), os.urandom(512>>3))
    bt[n] = int.from_bytes(n, "big")

    now = datetime.today()
    print("get: {}".format(bt.get(int(0).to_bytes(512>>3, "big"))))
    print("took: {}".format(datetime.today() - now))
    now = datetime.today()
    print("get: {}".format(bt.get(int(42).to_bytes(512>>3, "big"))))
    print("took: {}".format(datetime.today() - now))
    now = datetime.today()
    print("get: {}".format(bt.get(int(88).to_bytes(512>>3, "big"))))
    print("took: {}".format(datetime.today() - now))

    print("find speed test:")

    cnt = 42
    now = datetime.today()

    for i in bt.find(int(100).to_bytes(512>>3, "big")):
        print("find: {}".format(i))
        print("took: {}".format(datetime.today() - now))
        cnt -= 1
        if not cnt:
            break
        now = datetime.today()

def _validity_test():
    bt = BitTrie()
    #bt = {}

    for i in range(10):
        ri = random.randint(0, 100)
        k = ri.to_bytes(1, "big")

        now = datetime.today()
        r = bt[k] = ri
        print("put took: {}".format(datetime.today() - now))

    now = datetime.today()
    print("get: {}".format(bt.get(int(0).to_bytes(1, "big"))))
    print("took: {}".format(datetime.today() - now))
    now = datetime.today()
    print("get: {}".format(bt.get(int(42).to_bytes(1, "big"))))
    print("took: {}".format(datetime.today() - now))
    now = datetime.today()
    print("get: {}".format(bt.get(int(88).to_bytes(1, "big"))))
    print("took: {}".format(datetime.today() - now))

    cnt = 42
    now = datetime.today()
    for i in bt.find(int(42).to_bytes(1, "big")):
        print("find: {}".format(i))
#        print("took: {}".format(datetime.today() - now))
        cnt -= 1
        if not cnt:
            break
        now = datetime.today()

    print("<>")

    for i in bt.find(int(42).to_bytes(1, "big"), False):
        print("find: {}".format(i))
#        print("took: {}".format(datetime.today() - now))
        cnt -= 1
        if not cnt:
            break
        now = datetime.today()

def main():
    _del_test()
    _validity_test()
    _speed_test()

if __name__ == "__main__":
    main()
