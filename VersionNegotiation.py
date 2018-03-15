from scapy.fields import *
from scapy.packet import Packet


class VersionNegotiationPacket(Packet):
    name = "QUICVERSNEG"
    fields_desc = [
        XByteField("Public Flags", 0x0),
        XLongField("CID", int("0", 16)),
        XIntField("Version_1", 0),
        XIntField("Version_2", 0),
        XIntField("Version_3", 0),
        XIntField("Version_4", 0),
        XIntField("Version_5", 0),
    ]
