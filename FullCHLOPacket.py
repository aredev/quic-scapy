from scapy.fields import *
from scapy.packet import Packet

from util.SessionInstance import SessionInstance
from util.string_to_ascii import string_to_ascii


class FullCHLOPacket(Packet):
    """
    Full client hello packet
    Taken from Wireshark Capture example-local-clemente-aesgcm
    """
    name = "FullCHLO"

    fields_desc = [
        XByteField("Public Flags", 0x19),
        XLongField("CID", int("d75487b7da970f81", 16)),
        PacketField("Version", "Q039", "Q039"),
        LEShortField("Packet Number", 1024),

        # Message authentication hash
        StrFixedLenField("Message Authentication Hash", string_to_ascii(""), 12),

        XByteField("Frame Type", 0x84),
        XByteField("StreamId", 1),
        LEShortField("Offset", 4100),
        PacketField("Tag1", "CHLO", "CHLO"),
        LEShortField("Tag Number", 17),
        ShortField("Padding", 0),

        # List of tags
        PacketField("PAD", "PAD", "PAD"),
        ByteField("Xtra_1", 0),
        LEIntField("tag_offset_end_1", 637),

        PacketField("SNI", "SNI", "SNI"),
        ByteField("Xtra_2", 0),
        LEIntField("tag_offset_end_2", 652),

        PacketField("STK", "STK", "STK"),
        ByteField("Xtra_3", 0),
        LEIntField("tag_offset_end_3", 708),

        PacketField("SNO", "SNO", "SNO"),
        ByteField("Xtra_4", 0),
        LEIntField("tag_offset_end_4", 760),

        PacketField("VER", "VER", "VER"),
        ByteField("Xtra_5", 0),
        LEIntField("tag_offset_end_5", 764),

        PacketField("CCS", "CCS", "CCS"),
        ByteField("Xtra_6", 0),
        LEIntField("tag_offset_end_6", 780),

        PacketField("NONC", "NONC", "NONC"),
        LEIntField("tag_offset_end_7", 812),

        PacketField("AEAD", "AEAD", "AEAD"),
        LEIntField("tag_offset_end_8", 816),

        PacketField("SCID", "SCID", "SCID"),
        LEIntField("tag_offset_end_9", 832),

        PacketField("PDMD", "PDMD", "PDMD"),
        LEIntField("tag_offset_end_10", 836),

        PacketField("ICSL", "ICSL", "ICSL"),
        LEIntField("tag_offset_end_11", 840),

        PacketField("PUBS", "PUBS", "PUBS"),
        LEIntField("tag_offset_end_12", 872),

        PacketField("MIDS", "MIDS", "MIDS"),
        LEIntField("tag_offset_end_13", 876),

        PacketField("KEXS", "KEXS", "KEXS"),
        LEIntField("tag_offset_end_14", 880),

        PacketField("XLCT", "XLCT", "XLCT"),
        LEIntField("tag_offset_end_15", 888),

        PacketField("CFCW", "CFCW", "CFCW"),
        LEIntField("tag_offset_end_16", 892),

        PacketField("SFCW", "SFCW", "SFCW"),
        LEIntField("tag_offset_end_17", 896),

        XByteField("Padding0", 0x00),
        XByteField("Padding1", 0x00),
        XByteField("Padding2", 0x00),
        XByteField("Padding3", 0x00),
        XByteField("Padding4", 0x00),
        XByteField("Padding5", 0x00),
        XByteField("Padding6", 0x00),
        XByteField("Padding7", 0x00),
        XByteField("Padding8", 0x00),
        XByteField("Padding9", 0x00),
        XByteField("Padding10", 0x00),
        XByteField("Padding11", 0x00),
        XByteField("Padding12", 0x00),
        XByteField("Padding13", 0x00),
        XByteField("Padding14", 0x00),
        XByteField("Padding15", 0x00),
        XByteField("Padding16", 0x00),
        XByteField("Padding17", 0x00),
        XByteField("Padding18", 0x00),
        XByteField("Padding19", 0x00),
        XByteField("Padding20", 0x00),
        XByteField("Padding21", 0x00),
        XByteField("Padding22", 0x00),
        XByteField("Padding23", 0x00),
        XByteField("Padding24", 0x00),
        XByteField("Padding25", 0x00),
        XByteField("Padding26", 0x00),
        XByteField("Padding27", 0x00),
        XByteField("Padding28", 0x00),
        XByteField("Padding29", 0x00),
        XByteField("Padding30", 0x00),
        XByteField("Padding31", 0x00),
        XByteField("Padding32", 0x00),
        XByteField("Padding33", 0x00),
        XByteField("Padding34", 0x00),
        XByteField("Padding35", 0x00),
        XByteField("Padding36", 0x00),
        XByteField("Padding37", 0x00),
        XByteField("Padding38", 0x00),
        XByteField("Padding39", 0x00),
        XByteField("Padding40", 0x00),
        XByteField("Padding41", 0x00),
        XByteField("Padding42", 0x00),
        XByteField("Padding43", 0x00),
        XByteField("Padding44", 0x00),
        XByteField("Padding45", 0x00),
        XByteField("Padding46", 0x00),
        XByteField("Padding47", 0x00),
        XByteField("Padding48", 0x00),
        XByteField("Padding49", 0x00),
        XByteField("Padding50", 0x00),
        XByteField("Padding51", 0x00),
        XByteField("Padding52", 0x00),
        XByteField("Padding53", 0x00),
        XByteField("Padding54", 0x00),
        XByteField("Padding55", 0x00),
        XByteField("Padding56", 0x00),
        XByteField("Padding57", 0x00),
        XByteField("Padding58", 0x00),
        XByteField("Padding59", 0x00),
        XByteField("Padding60", 0x00),
        XByteField("Padding61", 0x00),
        XByteField("Padding62", 0x00),
        XByteField("Padding63", 0x00),
        XByteField("Padding64", 0x00),
        XByteField("Padding65", 0x00),
        XByteField("Padding66", 0x00),
        XByteField("Padding67", 0x00),
        XByteField("Padding68", 0x00),
        XByteField("Padding69", 0x00),
        XByteField("Padding70", 0x00),
        XByteField("Padding71", 0x00),
        XByteField("Padding72", 0x00),
        XByteField("Padding73", 0x00),
        XByteField("Padding74", 0x00),
        XByteField("Padding75", 0x00),
        XByteField("Padding76", 0x00),
        XByteField("Padding77", 0x00),
        XByteField("Padding78", 0x00),
        XByteField("Padding79", 0x00),
        XByteField("Padding80", 0x00),
        XByteField("Padding81", 0x00),
        XByteField("Padding82", 0x00),
        XByteField("Padding83", 0x00),
        XByteField("Padding84", 0x00),
        XByteField("Padding85", 0x00),
        XByteField("Padding86", 0x00),
        XByteField("Padding87", 0x00),
        XByteField("Padding88", 0x00),
        XByteField("Padding89", 0x00),
        XByteField("Padding90", 0x00),
        XByteField("Padding91", 0x00),
        XByteField("Padding92", 0x00),
        XByteField("Padding93", 0x00),
        XByteField("Padding94", 0x00),
        XByteField("Padding95", 0x00),
        XByteField("Padding96", 0x00),
        XByteField("Padding97", 0x00),
        XByteField("Padding98", 0x00),
        XByteField("Padding99", 0x00),
        XByteField("Padding100", 0x00),
        XByteField("Padding101", 0x00),
        XByteField("Padding102", 0x00),
        XByteField("Padding103", 0x00),
        XByteField("Padding104", 0x00),
        XByteField("Padding105", 0x00),
        XByteField("Padding106", 0x00),
        XByteField("Padding107", 0x00),
        XByteField("Padding108", 0x00),
        XByteField("Padding109", 0x00),
        XByteField("Padding110", 0x00),
        XByteField("Padding111", 0x00),
        XByteField("Padding112", 0x00),
        XByteField("Padding113", 0x00),
        XByteField("Padding114", 0x00),
        XByteField("Padding115", 0x00),
        XByteField("Padding116", 0x00),
        XByteField("Padding117", 0x00),
        XByteField("Padding118", 0x00),
        XByteField("Padding119", 0x00),
        XByteField("Padding120", 0x00),
        XByteField("Padding121", 0x00),
        XByteField("Padding122", 0x00),
        XByteField("Padding123", 0x00),
        XByteField("Padding124", 0x00),
        XByteField("Padding125", 0x00),
        XByteField("Padding126", 0x00),
        XByteField("Padding127", 0x00),
        XByteField("Padding128", 0x00),
        XByteField("Padding129", 0x00),
        XByteField("Padding130", 0x00),
        XByteField("Padding131", 0x00),
        XByteField("Padding132", 0x00),
        XByteField("Padding133", 0x00),
        XByteField("Padding134", 0x00),
        XByteField("Padding135", 0x00),
        XByteField("Padding136", 0x00),
        XByteField("Padding137", 0x00),
        XByteField("Padding138", 0x00),
        XByteField("Padding139", 0x00),
        XByteField("Padding140", 0x00),
        XByteField("Padding141", 0x00),
        XByteField("Padding142", 0x00),
        XByteField("Padding143", 0x00),
        XByteField("Padding144", 0x00),
        XByteField("Padding145", 0x00),
        XByteField("Padding146", 0x00),
        XByteField("Padding147", 0x00),
        XByteField("Padding148", 0x00),
        XByteField("Padding149", 0x00),
        XByteField("Padding150", 0x00),
        XByteField("Padding151", 0x00),
        XByteField("Padding152", 0x00),
        XByteField("Padding153", 0x00),
        XByteField("Padding154", 0x00),
        XByteField("Padding155", 0x00),
        XByteField("Padding156", 0x00),
        XByteField("Padding157", 0x00),
        XByteField("Padding158", 0x00),
        XByteField("Padding159", 0x00),
        XByteField("Padding160", 0x00),
        XByteField("Padding161", 0x00),
        XByteField("Padding162", 0x00),
        XByteField("Padding163", 0x00),
        XByteField("Padding164", 0x00),
        XByteField("Padding165", 0x00),
        XByteField("Padding166", 0x00),
        XByteField("Padding167", 0x00),
        XByteField("Padding168", 0x00),
        XByteField("Padding169", 0x00),
        XByteField("Padding170", 0x00),
        XByteField("Padding171", 0x00),
        XByteField("Padding172", 0x00),
        XByteField("Padding173", 0x00),
        XByteField("Padding174", 0x00),
        XByteField("Padding175", 0x00),
        XByteField("Padding176", 0x00),
        XByteField("Padding177", 0x00),
        XByteField("Padding178", 0x00),
        XByteField("Padding179", 0x00),
        XByteField("Padding180", 0x00),
        XByteField("Padding181", 0x00),
        XByteField("Padding182", 0x00),
        XByteField("Padding183", 0x00),
        XByteField("Padding184", 0x00),
        XByteField("Padding185", 0x00),
        XByteField("Padding186", 0x00),
        XByteField("Padding187", 0x00),
        XByteField("Padding188", 0x00),
        XByteField("Padding189", 0x00),
        XByteField("Padding190", 0x00),
        XByteField("Padding191", 0x00),
        XByteField("Padding192", 0x00),
        XByteField("Padding193", 0x00),
        XByteField("Padding194", 0x00),
        XByteField("Padding195", 0x00),
        XByteField("Padding196", 0x00),
        XByteField("Padding197", 0x00),
        XByteField("Padding198", 0x00),
        XByteField("Padding199", 0x00),
        XByteField("Padding200", 0x00),
        XByteField("Padding201", 0x00),
        XByteField("Padding202", 0x00),
        XByteField("Padding203", 0x00),
        XByteField("Padding204", 0x00),
        XByteField("Padding205", 0x00),
        XByteField("Padding206", 0x00),
        XByteField("Padding207", 0x00),
        XByteField("Padding208", 0x00),
        XByteField("Padding209", 0x00),
        XByteField("Padding210", 0x00),
        XByteField("Padding211", 0x00),
        XByteField("Padding212", 0x00),
        XByteField("Padding213", 0x00),
        XByteField("Padding214", 0x00),
        XByteField("Padding215", 0x00),
        XByteField("Padding216", 0x00),
        XByteField("Padding217", 0x00),
        XByteField("Padding218", 0x00),
        XByteField("Padding219", 0x00),
        XByteField("Padding220", 0x00),
        XByteField("Padding221", 0x00),
        XByteField("Padding222", 0x00),
        XByteField("Padding223", 0x00),
        XByteField("Padding224", 0x00),
        XByteField("Padding225", 0x00),
        XByteField("Padding226", 0x00),
        XByteField("Padding227", 0x00),
        XByteField("Padding228", 0x00),
        XByteField("Padding229", 0x00),
        XByteField("Padding230", 0x00),
        XByteField("Padding231", 0x00),
        XByteField("Padding232", 0x00),
        XByteField("Padding233", 0x00),
        XByteField("Padding234", 0x00),
        XByteField("Padding235", 0x00),
        XByteField("Padding236", 0x00),
        XByteField("Padding237", 0x00),
        XByteField("Padding238", 0x00),
        XByteField("Padding239", 0x00),
        XByteField("Padding240", 0x00),
        XByteField("Padding241", 0x00),
        XByteField("Padding242", 0x00),
        XByteField("Padding243", 0x00),
        XByteField("Padding244", 0x00),
        XByteField("Padding245", 0x00),
        XByteField("Padding246", 0x00),
        XByteField("Padding247", 0x00),
        XByteField("Padding248", 0x00),
        XByteField("Padding249", 0x00),
        XByteField("Padding250", 0x00),
        XByteField("Padding251", 0x00),
        XByteField("Padding252", 0x00),
        XByteField("Padding253", 0x00),
        XByteField("Padding254", 0x00),
        XByteField("Padding255", 0x00),
        XByteField("Padding256", 0x00),
        XByteField("Padding257", 0x00),
        XByteField("Padding258", 0x00),
        XByteField("Padding259", 0x00),
        XByteField("Padding260", 0x00),
        XByteField("Padding261", 0x00),
        XByteField("Padding262", 0x00),
        XByteField("Padding263", 0x00),
        XByteField("Padding264", 0x00),
        XByteField("Padding265", 0x00),
        XByteField("Padding266", 0x00),
        XByteField("Padding267", 0x00),
        XByteField("Padding268", 0x00),
        XByteField("Padding269", 0x00),
        XByteField("Padding270", 0x00),
        XByteField("Padding271", 0x00),
        XByteField("Padding272", 0x00),
        XByteField("Padding273", 0x00),
        XByteField("Padding274", 0x00),
        XByteField("Padding275", 0x00),
        XByteField("Padding276", 0x00),
        XByteField("Padding277", 0x00),
        XByteField("Padding278", 0x00),
        XByteField("Padding279", 0x00),
        XByteField("Padding280", 0x00),
        XByteField("Padding281", 0x00),
        XByteField("Padding282", 0x00),
        XByteField("Padding283", 0x00),
        XByteField("Padding284", 0x00),
        XByteField("Padding285", 0x00),
        XByteField("Padding286", 0x00),
        XByteField("Padding287", 0x00),
        XByteField("Padding288", 0x00),
        XByteField("Padding289", 0x00),
        XByteField("Padding290", 0x00),
        XByteField("Padding291", 0x00),
        XByteField("Padding292", 0x00),
        XByteField("Padding293", 0x00),
        XByteField("Padding294", 0x00),
        XByteField("Padding295", 0x00),
        XByteField("Padding296", 0x00),
        XByteField("Padding297", 0x00),
        XByteField("Padding298", 0x00),
        XByteField("Padding299", 0x00),
        XByteField("Padding300", 0x00),
        XByteField("Padding301", 0x00),
        XByteField("Padding302", 0x00),
        XByteField("Padding303", 0x00),
        XByteField("Padding304", 0x00),
        XByteField("Padding305", 0x00),
        XByteField("Padding306", 0x00),
        XByteField("Padding307", 0x00),
        XByteField("Padding308", 0x00),
        XByteField("Padding309", 0x00),
        XByteField("Padding310", 0x00),
        XByteField("Padding311", 0x00),
        XByteField("Padding312", 0x00),
        XByteField("Padding313", 0x00),
        XByteField("Padding314", 0x00),
        XByteField("Padding315", 0x00),
        XByteField("Padding316", 0x00),
        XByteField("Padding317", 0x00),
        XByteField("Padding318", 0x00),
        XByteField("Padding319", 0x00),
        XByteField("Padding320", 0x00),
        XByteField("Padding321", 0x00),
        XByteField("Padding322", 0x00),
        XByteField("Padding323", 0x00),
        XByteField("Padding324", 0x00),
        XByteField("Padding325", 0x00),
        XByteField("Padding326", 0x00),
        XByteField("Padding327", 0x00),
        XByteField("Padding328", 0x00),
        XByteField("Padding329", 0x00),
        XByteField("Padding330", 0x00),
        XByteField("Padding331", 0x00),
        XByteField("Padding332", 0x00),
        XByteField("Padding333", 0x00),
        XByteField("Padding334", 0x00),
        XByteField("Padding335", 0x00),
        XByteField("Padding336", 0x00),
        XByteField("Padding337", 0x00),
        XByteField("Padding338", 0x00),
        XByteField("Padding339", 0x00),
        XByteField("Padding340", 0x00),
        XByteField("Padding341", 0x00),
        XByteField("Padding342", 0x00),
        XByteField("Padding343", 0x00),
        XByteField("Padding344", 0x00),
        XByteField("Padding345", 0x00),
        XByteField("Padding346", 0x00),
        XByteField("Padding347", 0x00),
        XByteField("Padding348", 0x00),
        XByteField("Padding349", 0x00),
        XByteField("Padding350", 0x00),
        XByteField("Padding351", 0x00),
        XByteField("Padding352", 0x00),
        XByteField("Padding353", 0x00),
        XByteField("Padding354", 0x00),
        XByteField("Padding355", 0x00),
        XByteField("Padding356", 0x00),
        XByteField("Padding357", 0x00),
        XByteField("Padding358", 0x00),
        XByteField("Padding359", 0x00),
        XByteField("Padding360", 0x00),
        XByteField("Padding361", 0x00),
        XByteField("Padding362", 0x00),
        XByteField("Padding363", 0x00),
        XByteField("Padding364", 0x00),
        XByteField("Padding365", 0x00),
        XByteField("Padding366", 0x00),
        XByteField("Padding367", 0x00),
        XByteField("Padding368", 0x00),
        XByteField("Padding369", 0x00),
        XByteField("Padding370", 0x00),
        XByteField("Padding371", 0x00),
        XByteField("Padding372", 0x00),
        XByteField("Padding373", 0x00),
        XByteField("Padding374", 0x00),
        XByteField("Padding375", 0x00),
        XByteField("Padding376", 0x00),
        XByteField("Padding377", 0x00),
        XByteField("Padding378", 0x00),
        XByteField("Padding379", 0x00),
        XByteField("Padding380", 0x00),
        XByteField("Padding381", 0x00),
        XByteField("Padding382", 0x00),
        XByteField("Padding383", 0x00),
        XByteField("Padding384", 0x00),
        XByteField("Padding385", 0x00),
        XByteField("Padding386", 0x00),
        XByteField("Padding387", 0x00),
        XByteField("Padding388", 0x00),
        XByteField("Padding389", 0x00),
        XByteField("Padding390", 0x00),
        XByteField("Padding391", 0x00),
        XByteField("Padding392", 0x00),
        XByteField("Padding393", 0x00),
        XByteField("Padding394", 0x00),
        XByteField("Padding395", 0x00),
        XByteField("Padding396", 0x00),
        XByteField("Padding397", 0x00),
        XByteField("Padding398", 0x00),
        XByteField("Padding399", 0x00),
        XByteField("Padding400", 0x00),
        XByteField("Padding401", 0x00),
        XByteField("Padding402", 0x00),
        XByteField("Padding403", 0x00),
        XByteField("Padding404", 0x00),
        XByteField("Padding405", 0x00),
        XByteField("Padding406", 0x00),
        XByteField("Padding407", 0x00),
        XByteField("Padding408", 0x00),
        XByteField("Padding409", 0x00),
        XByteField("Padding410", 0x00),
        XByteField("Padding411", 0x00),
        XByteField("Padding412", 0x00),
        XByteField("Padding413", 0x00),
        XByteField("Padding414", 0x00),
        XByteField("Padding415", 0x00),
        XByteField("Padding416", 0x00),
        XByteField("Padding417", 0x00),
        XByteField("Padding418", 0x00),
        XByteField("Padding419", 0x00),
        XByteField("Padding420", 0x00),
        XByteField("Padding421", 0x00),
        XByteField("Padding422", 0x00),
        XByteField("Padding423", 0x00),
        XByteField("Padding424", 0x00),
        XByteField("Padding425", 0x00),
        XByteField("Padding426", 0x00),
        XByteField("Padding427", 0x00),
        XByteField("Padding428", 0x00),
        XByteField("Padding429", 0x00),
        XByteField("Padding430", 0x00),
        XByteField("Padding431", 0x00),
        XByteField("Padding432", 0x00),
        XByteField("Padding433", 0x00),
        XByteField("Padding434", 0x00),
        XByteField("Padding435", 0x00),
        XByteField("Padding436", 0x00),
        XByteField("Padding437", 0x00),
        XByteField("Padding438", 0x00),
        XByteField("Padding439", 0x00),
        XByteField("Padding440", 0x00),
        XByteField("Padding441", 0x00),
        XByteField("Padding442", 0x00),
        XByteField("Padding443", 0x00),
        XByteField("Padding444", 0x00),
        XByteField("Padding445", 0x00),
        XByteField("Padding446", 0x00),
        XByteField("Padding447", 0x00),
        XByteField("Padding448", 0x00),
        XByteField("Padding449", 0x00),
        XByteField("Padding450", 0x00),
        XByteField("Padding451", 0x00),
        XByteField("Padding452", 0x00),
        XByteField("Padding453", 0x00),
        XByteField("Padding454", 0x00),
        XByteField("Padding455", 0x00),
        XByteField("Padding456", 0x00),
        XByteField("Padding457", 0x00),
        XByteField("Padding458", 0x00),
        XByteField("Padding459", 0x00),
        XByteField("Padding460", 0x00),
        XByteField("Padding461", 0x00),
        XByteField("Padding462", 0x00),
        XByteField("Padding463", 0x00),
        XByteField("Padding464", 0x00),
        XByteField("Padding465", 0x00),
        XByteField("Padding466", 0x00),
        XByteField("Padding467", 0x00),
        XByteField("Padding468", 0x00),
        XByteField("Padding469", 0x00),
        XByteField("Padding470", 0x00),
        XByteField("Padding471", 0x00),
        XByteField("Padding472", 0x00),
        XByteField("Padding473", 0x00),
        XByteField("Padding474", 0x00),
        XByteField("Padding475", 0x00),
        XByteField("Padding476", 0x00),
        XByteField("Padding477", 0x00),
        XByteField("Padding478", 0x00),
        XByteField("Padding479", 0x00),
        XByteField("Padding480", 0x00),
        XByteField("Padding481", 0x00),
        XByteField("Padding482", 0x00),
        XByteField("Padding483", 0x00),
        XByteField("Padding484", 0x00),
        XByteField("Padding485", 0x00),
        XByteField("Padding486", 0x00),
        XByteField("Padding487", 0x00),
        XByteField("Padding488", 0x00),
        XByteField("Padding489", 0x00),
        XByteField("Padding490", 0x00),
        XByteField("Padding491", 0x00),
        XByteField("Padding492", 0x00),
        XByteField("Padding493", 0x00),
        XByteField("Padding494", 0x00),
        XByteField("Padding495", 0x00),
        XByteField("Padding496", 0x00),
        XByteField("Padding497", 0x00),
        XByteField("Padding498", 0x00),
        XByteField("Padding499", 0x00),
        XByteField("Padding500", 0x00),
        XByteField("Padding501", 0x00),
        XByteField("Padding502", 0x00),
        XByteField("Padding503", 0x00),
        XByteField("Padding504", 0x00),
        XByteField("Padding505", 0x00),
        XByteField("Padding506", 0x00),
        XByteField("Padding507", 0x00),
        XByteField("Padding508", 0x00),
        XByteField("Padding509", 0x00),
        XByteField("Padding510", 0x00),
        XByteField("Padding511", 0x00),
        XByteField("Padding512", 0x00),
        XByteField("Padding513", 0x00),
        XByteField("Padding514", 0x00),
        XByteField("Padding515", 0x00),
        XByteField("Padding516", 0x00),
        XByteField("Padding517", 0x00),
        XByteField("Padding518", 0x00),
        XByteField("Padding519", 0x00),
        XByteField("Padding520", 0x00),
        XByteField("Padding521", 0x00),
        XByteField("Padding522", 0x00),
        XByteField("Padding523", 0x00),
        XByteField("Padding524", 0x00),
        XByteField("Padding525", 0x00),
        XByteField("Padding526", 0x00),
        XByteField("Padding527", 0x00),
        XByteField("Padding528", 0x00),
        XByteField("Padding529", 0x00),
        XByteField("Padding530", 0x00),
        XByteField("Padding531", 0x00),
        XByteField("Padding532", 0x00),
        XByteField("Padding533", 0x00),
        XByteField("Padding534", 0x00),
        XByteField("Padding535", 0x00),
        XByteField("Padding536", 0x00),
        XByteField("Padding537", 0x00),
        XByteField("Padding538", 0x00),
        XByteField("Padding539", 0x00),
        XByteField("Padding540", 0x00),
        XByteField("Padding541", 0x00),
        XByteField("Padding542", 0x00),
        XByteField("Padding543", 0x00),
        XByteField("Padding544", 0x00),
        XByteField("Padding545", 0x00),
        XByteField("Padding546", 0x00),
        XByteField("Padding547", 0x00),
        XByteField("Padding548", 0x00),
        XByteField("Padding549", 0x00),
        XByteField("Padding550", 0x00),
        XByteField("Padding551", 0x00),
        XByteField("Padding552", 0x00),
        XByteField("Padding553", 0x00),
        XByteField("Padding554", 0x00),
        XByteField("Padding555", 0x00),
        XByteField("Padding556", 0x00),
        XByteField("Padding557", 0x00),
        XByteField("Padding558", 0x00),
        XByteField("Padding559", 0x00),
        XByteField("Padding560", 0x00),
        XByteField("Padding561", 0x00),
        XByteField("Padding562", 0x00),
        XByteField("Padding563", 0x00),
        XByteField("Padding564", 0x00),
        XByteField("Padding565", 0x00),
        XByteField("Padding566", 0x00),
        XByteField("Padding567", 0x00),
        XByteField("Padding568", 0x00),
        XByteField("Padding569", 0x00),
        XByteField("Padding570", 0x00),
        XByteField("Padding571", 0x00),
        XByteField("Padding572", 0x00),
        XByteField("Padding573", 0x00),
        XByteField("Padding574", 0x00),
        XByteField("Padding575", 0x00),
        XByteField("Padding576", 0x00),
        XByteField("Padding577", 0x00),
        XByteField("Padding578", 0x00),
        XByteField("Padding579", 0x00),
        XByteField("Padding580", 0x00),
        XByteField("Padding581", 0x00),
        XByteField("Padding582", 0x00),
        XByteField("Padding583", 0x00),
        XByteField("Padding584", 0x00),
        XByteField("Padding585", 0x00),
        XByteField("Padding586", 0x00),
        XByteField("Padding587", 0x00),
        XByteField("Padding588", 0x00),
        XByteField("Padding589", 0x00),
        XByteField("Padding590", 0x00),
        XByteField("Padding591", 0x00),
        XByteField("Padding592", 0x00),
        XByteField("Padding593", 0x00),
        XByteField("Padding594", 0x00),
        XByteField("Padding595", 0x00),
        XByteField("Padding596", 0x00),
        XByteField("Padding597", 0x00),
        XByteField("Padding598", 0x00),
        XByteField("Padding599", 0x00),
        XByteField("Padding600", 0x00),
        XByteField("Padding601", 0x00),
        XByteField("Padding602", 0x00),
        XByteField("Padding603", 0x00),
        XByteField("Padding604", 0x00),
        XByteField("Padding605", 0x00),
        XByteField("Padding606", 0x00),
        XByteField("Padding607", 0x00),
        XByteField("Padding608", 0x00),
        XByteField("Padding609", 0x00),
        XByteField("Padding610", 0x00),
        XByteField("Padding611", 0x00),
        XByteField("Padding612", 0x00),
        XByteField("Padding613", 0x00),
        XByteField("Padding614", 0x00),
        XByteField("Padding615", 0x00),
        XByteField("Padding616", 0x00),
        XByteField("Padding617", 0x00),
        XByteField("Padding618", 0x00),
        XByteField("Padding619", 0x00),
        XByteField("Padding620", 0x00),
        XByteField("Padding621", 0x00),
        XByteField("Padding622", 0x00),
        XByteField("Padding623", 0x00),
        XByteField("Padding624", 0x00),
        XByteField("Padding625", 0x00),
        XByteField("Padding626", 0x00),
        XByteField("Padding627", 0x00),
        XByteField("Padding628", 0x00),
        XByteField("Padding629", 0x00),
        XByteField("Padding630", 0x00),
        XByteField("Padding631", 0x00),
        XByteField("Padding632", 0x00),
        XByteField("Padding633", 0x00),
        XByteField("Padding634", 0x00),
        XByteField("Padding635", 0x00),
        XByteField("Padding636", 0x00),

        PacketField("Server Name Indication", "www.example.org", "www.example.org"),
        StrFixedLenField("STK_Value", string_to_ascii("f7214fe6649467547b2c4e006d97c716097d05ac737b34f426404fd965e2290677fecb437701364808ec4af796bacea645afd897525ef16f"), 56),
        StrFixedLenField("SNO_Value", string_to_ascii("e4d458e2594b930f6d4f77711215adf9ebe99096c479dbf765f41d28646c4b87a0ec735e63cc4f19b9207d369e36968b2b2071ed"), 52),
        LEIntField("Version_Value", 0),
        StrFixedLenField("CCS_Value", string_to_ascii("01e8816092921ae87eed8086a2158291"), 16),
        StrFixedLenField("NONC_Value", string_to_ascii("5ac349e90091b5556f1a3c52eb57f92c12640e876e26ab2601c02b2a32f54830"), 32),
        PacketField("AEAD_Value", "AESG", "AESG"),
        # Set the server config id to the value received in the REJ packet.
        StrFixedLenField("SCID_Value", "", 16),
        PacketField("PDMD_Value", "X509", "X509"),
        LEIntField("ICSL_Value", 30),
        StrFixedLenField("PUBS_Value", string_to_ascii("1403c2f3138a820f8114f282c4837d585bd00782f4ec0e5f1d39c06c49cc8043"), 32),
        LEIntField("MIDS_Value", 100),
        PacketField("KEXS_Value", "C255", "C255"),
        StrFixedLenField("XLCT_Value", string_to_ascii("7accfb0fbd674011"), 8),
        LEIntField("CFCW_Value", 49152),
        LEIntField("SFCW_Value", 32768),
    ]
