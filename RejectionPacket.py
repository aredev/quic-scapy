from scapy.packet import Packet
from scapy.fields import *

from XStrFixedLenField import XStrFixedLenField


class RejectionPacket(Packet):
    name = "REJPacket"
    fields_desc = [
        XByteField("Public Flags", 0x0),
        XLongField("CID", int("0", 16)),
        ByteField("Packet Number", 0),
        XStrFixedLenField("Message Authentication Hash", "", 12),
        XByteField("Frame_type", 0x0),
        XByteField("Stream_Id", 0x0),
        StrFixedLenField("Tag_1", "", 4),
        LEShortField("Tag_Number_1", 0),
        ShortField("Padding_1", 0),
        StrFixedLenField("Tag_2", "", 4),
        LEIntField("Tag_2_offset", 0),
        StrFixedLenField("Tag_3", "", 4),
        LEIntField("Tag_3_offset", 0),
        StrFixedLenField("Tag_4", "", 4),
        LEIntField("Tag_4_offset", 0),
        StrFixedLenField("Tag_5", "", 4),
        LEIntField("Tag_5_offset", 0),
        StrFixedLenField("Tag_6", "", 4),
        LEIntField("Tag_6_offset", 0),
        StrFixedLenField("Tag_7", "", 4),
        LEIntField("Tag_7_offset", 0),
        StrFixedLenField("Tag_8", "", 4),
        LEIntField("Tag_8_offset", 0),

        # Tag values incoming
        XStrFixedLenField("Source_Address_Token_Value", "", 56),
        XStrFixedLenField("Server_Nonce_Value", "", 52),
        XStrFixedLenField("Proof_Signature_Value", "", 256),
        # XStrFixedLenField("Server_Config_Value", "", 135),

        # Server config is special
        StrFixedLenField("Server_Config_Tag", "", 4),
        LEIntField("Number_Server_Config_Tag", 0),

        # First all the tags of the server config
        StrFixedLenField("AEAD_Tag", "", 4),
        LEIntField("AEAD_Tag_Offset", 0),

        StrFixedLenField("SCID_Tag", "", 4),
        LEIntField("SCID_Tag_Offset", 0),

        StrFixedLenField("PUBS_Tag", "", 4),
        LEIntField("PUBS_Tag_Offset", 0),

        StrFixedLenField("KEXS_Tag", "", 4),
        LEIntField("KEXS_Tag_Offset", 0),

        StrFixedLenField("OBIT_Tag", "", 4),
        LEIntField("OBIT_Tag_Offset", 0),

        StrFixedLenField("EXPY_Tag", "", 4),
        LEIntField("EXPY_Tag_Offset", 0),

        # Server config tag values

        XStrFixedLenField("AEAD_Value", "", 8),
        XStrFixedLenField("Server_Config_ID_Value", "", 16),
        XStrFixedLenField("Public_Value_Value", "", 35),
        XStrFixedLenField("KEXS_Value", "", 4),
        XStrFixedLenField("OBIT_Value", "", 8),
        XStrFixedLenField("EXPY_Value", "", 8),

        # Regular values

        XStrFixedLenField("RREJ_Value", "", 4),
        XStrFixedLenField("STTL_Value", "", 8),
        XStrFixedLenField("CRT_Value", "", 793),


    ]
