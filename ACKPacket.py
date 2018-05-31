from scapy.packet import Packet
from scapy.fields import *

from XStrFixedLenField import XStrFixedLenField
from util.string_to_ascii import string_to_ascii


class ACKPacket(Packet):
    name = "ACKPacket"
    fields_desc = [
        XByteField("Public Flags", 0x19),
        StrFixedLenField("CID", string_to_ascii(""), 8),
        StrFixedLenField("Version", "Q039", 4),
        LEShortField("Packet Number", 512),

        # Message authentication hash
        StrFixedLenField("Message Authentication Hash", string_to_ascii(""), 12),
        XByteField("Frame Type", 0x40),
        XByteField("Largest Acked", 2),
        LEShortField("Largest Acked Delta Time", 45362),
        XByteField("First Ack Block Length", 2),
        ByteField("Num Timestamp", 0),
    ]
