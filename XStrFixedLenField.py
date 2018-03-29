import binascii
from scapy.fields import StrFixedLenField


class XStrFixedLenField(StrFixedLenField):
    """
    StrFixedLenField which value is printed as hexadecimal.
    """

    def i2repr(self, pkt, x):
        if not x:
            return repr(x)
        return binascii.hexlify(x[:self.length_from(pkt)])
