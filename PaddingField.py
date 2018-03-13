from scapy.fields import FieldLenField


class PaddingField(FieldLenField):
    def addfield(self, pkt, s, val):
        return super().addfield(pkt, s, val)

    def getfield(self, pkt, s):
        return super().getfield(pkt, s)