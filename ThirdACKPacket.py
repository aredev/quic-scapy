from scapy.fields import *
from scapy.packet import Packet

from util.string_to_ascii import string_to_ascii


class ThirdACKPacket(Packet):
    name = "ThirdACKPacket"

    fields_desc = [
        XByteField("Public Flags", 0x18),
        XLongField("CID", int("d75487b7da970f81", 16)),
        LEShortField("Packet Number", 1280),

        # Message authentication hash
        StrFixedLenField("Message Authentication Hash", string_to_ascii(""), 12),
        XByteField("Frame Type", 0x56)
    ]
