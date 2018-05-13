from scapy.fields import *
from scapy.packet import Packet

from util.string_to_ascii import string_to_ascii


class AckNotificationPacket(Packet):
    """
    Holds the ack packet which will be send to the server.
    """
    name = "Ack Notification Packet"

    fields_desc = [
        XByteField("Public Flags", 0x18),
        StrFixedLenField("CID", string_to_ascii(""), 8),
        LEShortField("Packet Number", 512),

        # Message authentication hash
        StrFixedLenField("Message Authentication Hash", string_to_ascii(""), 12),
    ]
