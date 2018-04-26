from scapy.packet import Packet
from scapy.fields import *

from util.string_to_ascii import string_to_ascii


class PingPacket(Packet):
    name = "Ping Packet"

    fields_desc = [
        XByteField("Public Flags", 0x18),
        XLongField("CID", int("d75487b7da970f81", 16)),
        LEShortField("Packet Number", 768),

        # Message authentication hash
        StrFixedLenField("Message Authentication Hash", string_to_ascii(""), 12),
    ]
