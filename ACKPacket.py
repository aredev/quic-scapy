from scapy.packet import Packet
from scapy.fields import *

from XStrFixedLenField import XStrFixedLenField
from util.string_to_ascii import string_to_ascii


class ACKPacket(Packet):
    name = "ACKPacket"
    fields_desc = [
        XByteField("Public Flags", 0x19),
        StrFixedLenField("CID", string_to_ascii(""), 8),
        PacketField("Version", "Q039", "Q039"),
        LEShortField("Packet Number", 512),

        # Message authentication hash
        StrFixedLenField("Message Authentication Hash", string_to_ascii(""), 12),
        XByteField("Frame Type", 0x40),
        ByteField("Largest Acked", 1),
        LEShortField("Largest Acked Delta Time", 17408),
        ByteField("First Ack Block Length", 1),
        ByteField("Num Timestamp", 0),
    ]
