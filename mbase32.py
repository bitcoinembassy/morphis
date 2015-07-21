# Public Domain.

charset = "ybndrfg8ejkmcpqxot1uwisza345h769"

def encode(val):
    assert type(val) in (bytes, bytearray), type(val)

    result = ""

    r = 0
    rbits = 0

    for char in val:
        r = (r << 8) | char
        rbits += 8

        while rbits >= 5:
            rbits -= 5
            idx = r >> rbits
            r &= (1 << rbits) - 1

            result += charset[idx]

    if rbits:
        result += charset[r << (5 - rbits)]

    return result

def decode(val, padded=True):
    result = bytearray()

    a = 0
    abits = 0

    for char in val:
        a = (a << 5) | charset.index(char)
        abits += 5

        if abits >= 8:
            abits -= 8
            result.append(a >> abits)
            a &= (1 << abits) -1

    if not padded and abits:
        result.append(a << (8 - abits))

    return result
