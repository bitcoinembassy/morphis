import struct

import sshtype

class MNetPacket():
    def __init__(self, buf):
        if buf == None:
            self.buf = None
            return
        self.buf = buf

    def getPacketType(self):
        packet_type = struct.unpack("B", self.buf[0:1])[0]
        return packet_type

class MNetKexinitMessage(MNetPacket):
    def __init__(self, buf):
        super().__init__(buf)

        if buf != None:
            self.parse();

    def parse(self):
        i = 17;
        self.cookie = self.buf[1:i]

        l, v = sshtype.parseNameList(self.buf[i:])
        self.kex_algorithms = v
        i += l

    def getCookie(self):
        return self.cookie

    def getKeyExchangeAlgorithms(self):
        return self.kex_algorithms
