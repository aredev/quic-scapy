from scapy.fields import *
from scapy.packet import Packet

from XStrFixedLenField import XStrFixedLenField
from util.string_to_ascii import string_to_ascii


class AEADRequestPacket(Packet):
    """
    Class that holds the raw data for the AEAD Packets
    But without the div nonce, used for sending the requests.
    """
    name = "AEAD Packet"

    fields_desc = [
        XByteField("Public Flags", 0x0),
        StrFixedLenField("CID", string_to_ascii(""), 8),
        LEShortField("Packet Number", 0),
        XStrFixedLenField("Message Authentication Hash", string_to_ascii(""), 12),
    ]
