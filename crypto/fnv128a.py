import binascii
import struct

from crypto.GoogleFNV128Hash import GoogleFNV128Hash


class FNV128A:

    @staticmethod
    def print_like_go(info):
        info_as_string = "".join(map(chr, info))
        info_quic_style = [ord(c) for c in info_as_string]
        # print(info_quic_style)

    @staticmethod
    def generate_hash(associated_data, body, logging=False):
        h = GoogleFNV128Hash()

        logging = False
        h.write(associated_data, logging=logging)
        h.write(body, logging=logging)
        h.write("Client".encode("utf-8"), cast=False, logging=logging)

        big_endian_high, big_endian_low = h.sum128()
        # print("Low {} High {}".format(big_endian_low, big_endian_high))

        # The high part is casted to 32 bits
        big_endian_high &= 0xffffffff

        little_endian_low = struct.pack('<Q', big_endian_low).hex()
        little_endian_low_array = [little_endian_low[i:i+2] for i in range(0, len(little_endian_low), 2)]
        little_endian_high = struct.pack('<Q', big_endian_high).hex()
        little_endian_high_array = [little_endian_high[i:i+2] for i in range(0, len(little_endian_high), 2)]

        full_hash_len = 12 + len(body)
        full_hash = [0] * full_hash_len
        full_hash[0:len(body)] = body
        full_hash[12:12+len(body)] = body

        full_hash[:8] = little_endian_low_array
        full_hash[8:12] = little_endian_high_array[:4]
        message_authentication_hash = "".join(full_hash)
        # print(message_authentication_hash[:24])
        return message_authentication_hash[:24]

    @staticmethod
    def test_hash():
        """
        :return:
        """
        h = GoogleFNV128Hash()

        associated_data = bytes([25, 141, 79, 108, 243, 212, 21, 72, 12, 81, 48, 51, 57, 0, 1])
        # print(associated_data)
        h.write(associated_data)

        source_as_string = "[128 1 67 72 76 79 9 0 0 0 80 65 68 0 137 3 0 0 83 78 73 0 152 3 0 0 86 69 82 0 156 3 0 0 67 67 83 0 172 3 0 0 80 68 77 68 176 3 0 0 73 67 83 76 180 3 0 0 77 73 68 83 184 3 0 0 67 70 67 87 188 3 0 0 83 70 67 87 192 3 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 119 119 119 46 101 120 97 109 112 108 101 46 111 114 103 0 0 0 0 1 232 129 96 146 146 26 232 126 237 128 134 162 21 130 145 88 53 48 57 30 0 0 0 100 0 0 0 0 192 0 0 0 128 0 0]"
        source_as_string = source_as_string.replace("[", "")
        source_as_string = source_as_string.replace("]", "")
        source_as_array = source_as_string.split(" ")
        source_as_array = [int(x) for x in source_as_array]
        h.write(bytes(source_as_array))

        h.write("Client".encode("utf-8"))

        big_endian_high, big_endian_low = h.sum128()
        # print("Low {} High {}".format(big_endian_low, big_endian_high))
        # print("High equal {}".format(big_endian_high == 3982203028265477082))
        # print("Low equal {}".format(big_endian_low == 1587784438202799035))

        little_endian_low = struct.pack('<Q', big_endian_low)
        little_endian_high = struct.pack('<Q', big_endian_high)

        full_hash = little_endian_low + little_endian_high
        # print(binascii.hexlify(full_hash[:12]))

# associated_data = "'19', '63', 'CD', '37', '66', 'FD', 'B7', 'C9', 'B8', '51', '30', '33', '39', '00', '02'".replace("\'", "").replace(",", "")
# associated_data = associated_data.split(" ")
# #
# body = "'40', '01', '00', '44', '01', '00'".replace("\'", "").replace(",", "")
# body = body.split(" ")
# FNV128A.generate_hash(associated_data, body, logging=True)
