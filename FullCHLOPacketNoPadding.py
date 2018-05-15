from scapy.fields import *
from scapy.packet import Packet

from util.SessionInstance import SessionInstance
from util.string_to_ascii import string_to_ascii


class FullCHLOPacketNoPadding(Packet):
    """
    Full client hello packet
    Taken from Wireshark Capture example-local-clemente-aesgcm
    """
    name = "FullCHLO"

    fields_desc = [
        XByteField("Public Flags", 0x19),
        StrFixedLenField("CID", string_to_ascii(""), 8),
        PacketField("Version", "Q039", "Q039"),
        LEShortField("Packet Number", 1024),

        # Message authentication hash
        StrFixedLenField("Message Authentication Hash", string_to_ascii(""), 12),
    ]
