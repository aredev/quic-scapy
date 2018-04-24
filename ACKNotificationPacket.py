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
        XLongField("CID", int("d75487b7da970f81", 16)),
        LEShortField("Packet Number", 512),

        # Message authentication hash
        StrFixedLenField("Message Authentication Hash", string_to_ascii(""), 12),
    ]
