from scapy.packet import Packet
from scapy.fields import *

from util.string_to_ascii import string_to_ascii


class SecondACKPacket(Packet):
    name = "ACKPacket 2"
    fields_desc = [
        XByteField("Public Flags", 0x19),
        StrFixedLenField("CID", string_to_ascii(""), 8),
        PacketField("Version", "Q039", "Q039"),
        LEShortField("Packet Number", 768),

        # Message authentication hash
        StrFixedLenField("Message Authentication Hash", string_to_ascii("08c9ea3eed281184a3fd65a5"), 12),
        XByteField("Frame Type", 0x40),
        ByteField("Largest Acked", 2),
        LEShortField("Largest Acked Delta Time", 1108),
        ByteField("First Ack Block Length", 2),
        ByteField("Num Timestamp", 0),
    ]