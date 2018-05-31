import struct

from crypto.dhke import dhke
from events.Exceptions import NotHtmlNorSHLOException, NotSHLOButHtmlException, NotSHLOButCloseException
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
        print("SHLO Packet Processor received body {}".format(body))

    def read_byte(self, n=1):
        slice = self.packet_body[self.reader:self.reader+n]
        self.reader += n
        return "".join(slice)

    def parse_type(self):
        """
        Take the first byte as bits and perform the following checks
        :return:
        """
        first_byte = self.read_byte()
        if first_byte == "02":
            # connection closed
            raise NotSHLOButCloseException()
        first_byte_as_bits = bin(int(first_byte, base=16))[2:].zfill(8)

        if first_byte_as_bits[0] != '1':
            raise ValueError("This is not a stream!")
        else:
            self.data_length_present = first_byte_as_bits[2] == '1'
            self.offset_length = self.offset_lengths[int(first_byte_as_bits[3:6], 2)]
            self.stream_id_length = self.stream_id_lengths[int(first_byte_as_bits[7:8], 2)]

            self.stream_id = self.read_byte(self.stream_id_length)
            print("Stream Id {}".format(self.stream_id))
            if not self.stream_id == "01" and not self.stream_id == "05":
                # If it not stream 1 or stream 5, then it is not SHLO or HTML
                raise NotHtmlNorSHLOException()
            elif not self.stream_id == "01" and self.stream_id == "05":
                # If it is not stream 1 but it is stream 5, then probably it is HTML.
                raise NotSHLOButHtmlException()
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
        if tag == "53484c4f":
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
                    SessionInstance.get_instance().peer_public_value = bytes.fromhex(tag['value'])
                elif "SNO".encode('utf-8') in tag['tag']:
                    SessionInstance.get_instance().server_nonce = tag['value']
            print(tags)
            SessionInstance.get_instance().last_received_shlo = SessionInstance.get_instance().message_authentication_hash

            return True
        return False

