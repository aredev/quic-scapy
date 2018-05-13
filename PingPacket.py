from scapy.packet import Packet
from scapy.fields import *

from util.string_to_ascii import string_to_ascii


class PingPacket(Packet):
    name = "Ping Packet"

    fields_desc = [
        XByteField("Public Flags", 0x18),
        StrFixedLenField("CID", string_to_ascii(""), 8),
        LEShortField("Packet Number", 768),

        # Message authentication hash
        StrFixedLenField("Message Authentication Hash", string_to_ascii(""), 12),
    ]
