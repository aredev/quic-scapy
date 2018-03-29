from scapy.fields import *
from scapy.packet import Packet


class FullCHLOPacket(Packet):
    name = "FullCHLO"

    fields_desc = [
        XByteField("Public Flags", 0x0c),
        XLongField("CID", int("39b18ffea95af9fb", 16)),
        ByteField("Packet Number", 3),

        # Message authentication hash
        XByteField("message_authentication_hash0", 0xf5),
        XByteField("message_authentication_hash1", 0x85),
        XByteField("message_authentication_hash2", 0x12),
        XByteField("message_authentication_hash3", 0x36),
        XByteField("message_authentication_hash4", 0x20),
        XByteField("message_authentication_hash5", 0x8f),
        XByteField("message_authentication_hash6", 0xbb),
        XByteField("message_authentication_hash7", 0xdc),
        XByteField("message_authentication_hash8", 0x5b),
        XByteField("message_authentication_hash9", 0x9a),
        XByteField("message_authentication_hash10", 0x9c),
        XByteField("message_authentication_hash11", 0x34),

        XByteField("Frame Type", 0xa4),
        XByteField("StreamId", 1),
        LEShortField("Data Length", 5125),
        PacketField("Tag1", "CHLO", "CHLO"),
        LEShortField("Tag Number", 24),
        ShortField("Padding", 0),

        # List of tags
        PacketField("PAD", "PAD", "PAD"),
        ByteField("Xtra", 0),
        LEIntField("tag_offset_end", 505),

        PacketField("SNI", "SNI", "SNI"),
        ByteField("Xtra", 0),
        LEIntField("tag_offset_end", 520),

        PacketField("STK", "STK", "STK"),
        ByteField("Xtra", 0),
        LEIntField("tag_offset_end", 576),

        PacketField("SNO", "SNO", "SNO"),
        ByteField("Xtra", 0),
        LEIntField("tag_offset_end", 628),

        PacketField("VER", "VER", "VER"),
        ByteField("Xtra", 0),
        LEIntField("tag_offset_end", 632),

        PacketField("CCS", "CCS", "CCS"),
        ByteField("Xtra", 0),
        LEIntField("tag_offset_end", 648),

        PacketField("NONC", "NONC", "NONC"),
        ByteField("Xtra", 0),
        LEIntField("tag_offset_end", 680),

        PacketField("MSPC", "MSPC", "MSPC"),
        ByteField("Xtra", 0),
        LEIntField("tag_offset_end", 684),

        PacketField("AEAD", "AEAD", "AEAD"),
        ByteField("Xtra", 0),
        LEIntField("tag_offset_end", 688),

        PacketField("AEAD", "AEAD", "AEAD"),
        ByteField("Xtra", 0),
        LEIntField("tag_offset_end", 688),
    ]