from scapy.fields import *
from scapy.packet import Packet

from XStrFixedLenField import XStrFixedLenField
from util.string_to_ascii import string_to_ascii


class AEADPacket(Packet):
    """
    Class that holds the raw data for the AEAD Packets
    """
    name = "AEAD Packet"

    fields_desc = [
        XByteField("Public Flags", 0x0),
        XLongField("CID", int("d75487b7da970f81", 16)),
        XStrFixedLenField("Diversification Nonce", string_to_ascii(""), 32),
        ByteField("Packet Number", 0),
        XStrFixedLenField("Message Authentication Hash", string_to_ascii(""), 12),
    ]
