from operator import xor

class GoogleFNV128Hash:
    """
    Since Google does things different than everyone else, the FNV hash according to their QUIC implementation
    Ported from Clemente's GO implementation
    """

    sum = {
        'v0': 0x6295C58D,
        'v1': 0x62B82175,
        'v2': 0x07BB0142,
        'v3': 0x6C62272E
    }

    def new(self):
        return self.sum

    def sum128(self):
        print("Input for hash: {}".format(self.sum))
        return self.sum['v3'] << 32 | self.sum['v2'], self.sum['v1'] << 32 | self.sum['v0']

    def write(self, data, cast=True):
        """
        Data is now a full string received from the
        :param cast:
        :param data:
        :return:
        """
        fnv128prime_low = 0x0000013B
        fnv128prime_shift = 24

        for byte in data:
            if cast:
                byte = int(byte, 16)

            self.sum['v0'] ^= byte

            t0 = self.sum['v0'] * fnv128prime_low
            t1 = self.sum['v1'] * fnv128prime_low
            t2 = ( self.sum['v2'] * fnv128prime_low ) + ( self.sum['v0'] << fnv128prime_shift )
            t3 = ( self.sum['v3'] * fnv128prime_low ) + ( self.sum['v1'] << fnv128prime_shift )

            t1 += (t0 >> 32)
            t2 += (t1 >> 32)
            t3 += (t2 >> 32)

            self.sum['v0'] = t0 & 0xffffffff
            self.sum['v1'] = t1 & 0xffffffff
            self.sum['v2'] = t2 & 0xffffffff
            self.sum['v3'] = t3 & 0xffffffff

        return len(data)
