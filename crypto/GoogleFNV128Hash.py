import string
import time
from operator import xor
import random


class GoogleFNV128Hash:
    """
    Since Google does things different than everyone else, the FNV hash according to their QUIC implementation
    Ported from Clemente's GO implementation
    """

    def __init__(self) -> None:
        self.sum = {
            'v0': 0x6295C58D,
            'v1': 0x62B82175,
            'v2': 0x07BB0142,
            'v3': 0x6C62272E
        }

    sum = {
        'v0': 0x6295C58D,
        'v1': 0x62B82175,
        'v2': 0x07BB0142,
        'v3': 0x6C62272E
    }

    def new(self):
        return self.sum

    def sum128(self):
        return self.sum['v3'] << 32 | self.sum['v2'], self.sum['v1'] << 32 | self.sum['v0']

    def write(self, data, cast=True, logging=False):
        """
        Data is now a full string received from the
        :param cast:
        :param data:
        :return:
        """
        fnv128prime_low = 0x0000013B
        fnv128prime_shift = 24
        if logging:
            filename = "log1" + ".txt"
            log_file = open(filename, "a")

        # Resetting the values?

        for byte in data:
            if logging:
                log_file.write("**** CALCULATING WITH UNCASTED BYTE {} \n".format(byte))

            if cast:
                byte = int(byte, 16)

            if logging:
                log_file.write("**** CALCULATING WITH CASTED BYTE {} \n".format(byte))

            if logging:
                log_file.write("SUM: {} \n".format(self.sum))

            self.sum['v0'] ^= byte

            if logging:
                log_file.write("After xor {} \n".format(self.sum))

            t0 = self.sum['v0'] * fnv128prime_low
            if logging:
                log_file.write("After mult {} \n".format(t0))

            t1 = self.sum['v1'] * fnv128prime_low
            if logging:
                log_file.write("After mult 2 {} \n".format(t1))

            t2 = (self.sum['v2'] * fnv128prime_low) + (self.sum['v0'] << fnv128prime_shift)
            if logging:
                log_file.write("After mult 3 {} \n".format(t2))

            t3 = (self.sum['v3'] * fnv128prime_low) + (self.sum['v1'] << fnv128prime_shift)
            if logging:
                log_file.write("After mult 4 {} \n".format(t3))

            t1 += (t0 >> 32)
            if logging:
                log_file.write("After shift {} \n".format(t1))

            t2 += (t1 >> 32)
            if logging:
                log_file.write("After shift 2 {} \n".format(t2))

            t3 += (t2 >> 32)
            if logging:
                log_file.write("After shift 3 {} \n".format(t3))

            self.sum['v0'] = t0 & 0xffffffff
            if logging:
                log_file.write("After end {} \n".format(self.sum))

            self.sum['v1'] = t1 & 0xffffffff
            if logging:
                log_file.write("After end 2 {} \n".format(self.sum))

            self.sum['v2'] = t2 & 0xffffffff
            if logging:
                log_file.write("After end 3 {} \n".format(self.sum))

            self.sum['v3'] = t3 & 0xffffffff
            if logging:
                log_file.write("After end 4 {} \n".format(self.sum))

            if logging:
                log_file.write("SUM: {} \n".format(self.sum))
                log_file.write("**** FINISHED CALCULATION WITH BYTE {} \n \n \n".format(byte))

        # print(self.sum)
        return len(data)
