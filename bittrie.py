class BitTrie(object):
    def __init__(self):
        self.trie = [None, None]

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

    def put(self, key, value):
        node = self.trie

        keylen = len(key)
        for i in range(keylen):
            char = key[i]
            for j in range(7, -1, -1):
                bit = (char >> j) & 0x01
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
                            node[bit] = TrieLeaf(key, value)
                            return other.value

                        next_o_bit = (o_key[i+1] >> 7) & 0x01
                    else:
                        next_o_bit = (o_key[i] >> (j-1)) & 0x01

                    next_node = [None, None]
                    next_node[next_o_bit] = other

                    node[bit] = next_node
                    node = next_node
                    continue

                assert type(next_node) is list
                node = next_node

    def _del(self, key):
        prev_node = None
        prev_node_bit = None
        node = self.trie

        for i in range(len(key)):
            char = key[i]
            for j in range(7, -1, -1):
                bit = (char >> j) & 0x01
                next_node = node[bit]

                if not next_node:
                    return None

                if type(next_node) is TrieLeaf:
                    other_bit = bit ^ 0x01
                    if node[other_bit]:
                        node[bit] = None
                    else:
                        if prev_node:
                            prev_node[prev_node_bit] = None

                    return next_node.value

                assert type(next_node) is list

                prev_node = node
                prev_node_bit = bit
                node = next_node

    def _get(self, key):
        node = self.trie

        for i in range(len(key)):
            char = key[i]
            for j in range(7, -1, -1):
                bit = (char >> j) & 0x01
                next_node = node[bit]

                if not next_node:
                    return None

                if type(next_node) is TrieLeaf:
                    if next_node.key == key:
                        return next_node.value
                    else:
                        return None

                assert type(next_node) is list

                node = next_node

    def _find(self, key):
        "Generator."
        branches = []
        node = self.trie

        key_len = len(key)
        i = 0
        while i < key_len:
            char = key[i]
            j = 7
            while j >= 0:
                bit = (char >> j) & 0x01

                if not bit:
                    other = node[1]
                    if other != None:
                        branches.append(other)
                    next_node = node[0]
                else:
                    next_node = node[1]

                if not next_node:
                    yield None
                    for r in self._iterate_next(branches):
                        yield r
                    return None

                if type(next_node) is TrieLeaf:
                    yield next_node.value
                    for r in self._iterate_next(branches):
                        yield r
                    return None

                assert type(next_node) is list

                node = next_node
                j = j - 1

            i = i + 1

    def _iterate_next(self, branches):
        while True:
            if not branches:
                return None

            node = branches.pop()

            while True:
                if type(node) is TrieLeaf:
                    yield node.value
                    break

                assert type(node) is list

                obj = node[0]
                if obj:
                    if node[1]:
                        branches.append(node[1])
                    node = obj
                else:
                    node = node[1]

class TrieLeaf(object):
    def __init__(self, key, value):
        self.key = key
        self.value = value

import random
from datetime import datetime

print("HI")

bt = BitTrie()
#bt = {}

for i in range(50000):
    val = random.randint(0, pow(2, 512)-1)

    ib = val.to_bytes(512, "big")

    now = datetime.today()
    r = bt.put(ib, val)
    #r = bt[val] = val
    if not i % 5000:
        print("put took: {}".format(datetime.today() - now))
#    if r:
#        print("dup")

now = datetime.today()
print("get: {}".format(bt.get(int(0).to_bytes(512, "big"))))
print("took: {}".format(datetime.today() - now))
now = datetime.today()
print("get: {}".format(bt.get(int(42).to_bytes(512, "big"))))
print("took: {}".format(datetime.today() - now))

cnt = 42
now = datetime.today()
for i in bt._find(int(100).to_bytes(512, "big")):
    print("find: {}".format(i))
    print("took: {}".format(datetime.today() - now))
    cnt -= 1
    if not cnt:
        break
    now = datetime.today()
