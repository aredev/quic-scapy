import struct

from util.SessionInstance import SessionInstance


class SHLOPacketProcessor:
    """
    Processes the unencrypted SHLO packet
    """

    packet_body = None
    reader = 0
    data_length_present = False
    offset_length = -1
    stream_id_length = -1
    offset_lengths = [0, 2, 3, 4, 5, 6, 7, 8]
    stream_id_lengths = [1, 2, 3, 4]
    data_length = -1

    stream_id = None
    offset = None

    def __init__(self, body) -> None:
        self.packet_body = body

    def read_byte(self, n=1):
        slice = self.packet_body[self.reader:self.reader+n*2]
        self.reader += n*2
        return slice

    def parse_type(self):
        """
        Take the first byte as bits and perform the following checks
        :return:
        """
        first_byte_as_bits = bin(int(self.read_byte(), base=16))[2:].zfill(8)
        if first_byte_as_bits[0] != '1':
            raise ValueError("This is not a stream!")
        else:
            self.data_length_present = first_byte_as_bits[2] == '1'
            self.offset_length = self.offset_lengths[int(first_byte_as_bits[3:6])]
            self.stream_id_length = self.stream_id_lengths[int(first_byte_as_bits[7:8])]

            self.stream_id = self.read_byte(self.stream_id_length)
            self.offset = self.read_byte(self.offset_length)

            if self.data_length_present:
                self.data_length = self.read_byte(2)

    def parse(self):
        """
        :return:
        """
        tags = []
        self.parse_type()
        tag = self.read_byte(4)
        tag_number = self.read_byte(2)
        tag_number = struct.unpack("<h", bytes.fromhex(tag_number))[0]  # Number of tags that need to be processed
        self.read_byte(2)

        offset = 0
        for i in range(0, tag_number):
            tag = bytes.fromhex(self.read_byte(4))
            length = struct.unpack("<i", bytes.fromhex(self.read_byte(4)))[0]

            length = length - offset
            offset += length

            tags.append({
                'tag': tag,
                'length': length
            })

        for tag in tags:
            tag['value'] = self.read_byte(tag['length'])
            if "PUBS".encode('utf-8') in tag['tag']:
                print("Setting peer public value")
                SessionInstance.get_instance().peer_public_value = bytes.fromhex(tag['value'])
            elif "SNO".encode('utf-8') in tag['tag']:
                print("Setting SNO")
                SessionInstance.get_instance().server_nonce = tag['value']
        print(tags)


# shlo = SHLOPacketProcessor("a4010558014e53484c4f0d00000053544b0036000000534e4f006a000000564552007e0000004d53504382000000534d484c860000004943534c8a000000434144529e00000050554253be0000004d494453c200000053434c53c600000053525354d600000043464357da00000053464357de0000004fbfafb5828abb2160c9ca2a5449eef29e3724bd6c748ee5ef2912d83ad65cf71df218c93979229231142082d7e6b822305fac615bfde92c68fba3330658603a9799499b9c9f1504baa1a6f16983fc5b4213cc6af86c3e31cb67d43a4b74ebf50790492ded8a6050cd41513034315130333951303338513033375130333564000000010000001e0000000a0000000000000000000000ffffc0a8014b42ef0fd5be04c01b9702a26e2d9e449b6cd91f08f014f9cebb37a883df7965b24f3d6400000000000000b5690f0000000000000000000000000000001000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000897d1ffdf804de8a2be20fefc9cccace22680de0b42f8c24")
# shlo.parse()
