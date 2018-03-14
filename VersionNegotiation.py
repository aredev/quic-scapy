from scapy.fields import *
from scapy.packet import Packet


class VersionNegotiationPacket(Packet):
    name = "QUICVERSNEG"
    fields_desc = [
        # StrField("Bla", "")
        XByteField("Public Flags", 0x0d),
        XLongField("CID", int("f5789f791843c6a7", 16)),
        StrFixedLenField("Version_1", "", 4)
        # PacketField("Version_1", "Q099", ""),
        # PacketField("Version_2", "Q099", ""),
        # PacketField("Version_3", "Q099", ""),
        # PacketField("Version_4", "Q099", ""),
        # PacketField("Version_5", "Q099", ""),
    ]

    def get_field(self, fld):
        print(fld)

    def do_dissect(self, s):
        field_list = self.fields_desc[:]
        field_list.reverse()
        while s and field_list:
            f = field_list.pop()
            s, f_val = f.getfield(self, s)
            print(f_val)
            self.fields[f] = f_val
        return s
