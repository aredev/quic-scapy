from enum import Enum


class AEADPacketDynamic:
    """
    Custom holder for this packet
    """
    packet_body = None
    reader = 0
    fields = {}
    packet_number_lengths = {'0x0': 1, '0x1': 2, '0x2': 4, '0x3': 6}
    packet_number_length = -1
    is_public_reset = False
    div_nonce_present = False
    conn_id_present = False

    def __init__(self, packet: bytes) -> None:
        self.packet_body = None
        self.reader = 0
        self.fields = {}
        self.packet_number_lengths = {'0x0': 1, '0x1': 2, '0x2': 4, '0x3': 6}
        self.packet_number_length = -1
        self.is_public_reset = False
        self.div_nonce_present = False
        self.conn_id_present = False
        self.packet_body = packet

    def read_byte(self, n=1):
        data = self.packet_body[self.reader:self.reader+n]
        self.reader += n
        return data

    def get_field(self, name):
        for n, value in self.fields.items():
            if n == name:
                return value
        return "NOT FOUND"

    def has_field(self, name):
        for n, value in self.fields.items():
            if n == name:
                return True

        return False

    def get_packet(self):
        return self.packet_body

    def get_associated_data(self):
        result = self.get_field(AEADFieldNames.PUBLIC_FLAGS)
        if self.conn_id_present:
            result += self.get_field(AEADFieldNames.CID)

        if self.div_nonce_present:
            result += self.get_field(AEADFieldNames.DIVERSIFICATION_NONCE)

        result += self.get_field(AEADFieldNames.PACKET_NUMBER)
        # result += self.get_field(AEADFieldNames.MESSAGE_AUTHENTICATION_HASH)

        return result

    def parse(self):
        self.check_flags()
        self.parse_header()

        self.fields.update({
            AEADFieldNames.ENCRYPTED_FRAMES: self.packet_body[self.reader:].hex()
        })

    def check_flags(self):
        """
        Convert first byte to
        :return:
        """
        public_flags = self.read_byte()
        self.fields.update({
            AEADFieldNames.PUBLIC_FLAGS: public_flags.hex()
        })

        public_flags_as_bits = bin(int(public_flags.hex(), 16))[2:].zfill(8)
        self.is_public_reset = public_flags_as_bits[6] == '1'
        self.div_nonce_present = public_flags_as_bits[5] == '1'
        self.conn_id_present = public_flags_as_bits[4] == '1'

        public_flag_bits = public_flags_as_bits[2:4]
        public_flag_bytes = hex(int(public_flag_bits, 2))
        self.packet_number_length = self.packet_number_lengths[public_flag_bytes]

    def parse_header(self):
        if self.conn_id_present:
            self.fields.update({
                AEADFieldNames.CID: self.read_byte(8).hex()
            })

        if self.div_nonce_present:
            div_nonce = self.read_byte(32).hex()
            self.fields.update({
                AEADFieldNames.DIVERSIFICATION_NONCE: div_nonce
            })

        self.fields.update({
            AEADFieldNames.PACKET_NUMBER: self.read_byte(self.packet_number_length).hex()
        })

        self.fields.update({
            AEADFieldNames.MESSAGE_AUTHENTICATION_HASH: self.read_byte(12).hex()
        })


class AEADFieldNames(Enum):
    PUBLIC_FLAGS = "Public Flags"
    CID = "CID"
    PACKET_NUMBER = "Packet Number"
    MESSAGE_AUTHENTICATION_HASH = "Message Authentication Hash"
    ENCRYPTED_FRAMES = "Encrypted Frames"
    DIVERSIFICATION_NONCE = "Diversification Nonce"
