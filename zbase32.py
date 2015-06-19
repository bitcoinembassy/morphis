# Public Domain.

charset = "ybndrfg8ejkmcpqxot1uwisza345h769"

def encode(val):
    if type(val) is not int:
        val = int.from_bytes(val, "big")

    result = ""

    while val > 0:
        result = charset[val % 32] + result
        val >>= 5 # Divide by 32.

    return result

def decode(val, origlen):
    result = _decode(val, origlen)
    return result.to_bytes(origlen, "big")

def _decode(val, origlen):
    result = 0

    for char in val:
        result *= 32
        result += charset.index(char)

    return result
