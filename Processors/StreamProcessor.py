from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from Processors.Processor import Processor
from util.SessionInstance import SessionInstance
from util.processor_hex_number_to_int import processor_hex_to_int


class StreamProcessor(Processor):
    packet_body = None
    data_length_present = False
    data_length = None  # 4 bytes
    offset = None  # 0, 16, 24, 32, 40, 48, 56, 64 bits
    offset_length = 0
    stream_id = None  # 8, 16, 24, 32 bits
    stream_length = 0

    reader = 0  # Index for the reader

    plaintext = ""
    first_byte_as_bits = None

    def my_frame(self):
        self.first_byte_as_bits = bin(int(self.packet_body[self.reader], base=16))[2:].zfill(8)
        return self.first_byte_as_bits[0] == "1"

    def parse_frame_header(self):
        """
        First determine what is present then get it in the following order:
        Stream ID || Offset || Data Length
        :return:
        """
        self.reader += 1
        self.data_length_present = self.first_byte_as_bits[2] == "1"

        available_offsets = [0, 2, 3, 4, 5, 6, 7, 8]  # in bytes
        available_streams = [1, 2, 3, 4]

        self.offset_length = available_offsets[int(self.first_byte_as_bits[3:6], 2)]  # convert to bytes
        # Extract offset_length from the packet to determine the offset
        self.stream_length = available_streams[int(self.first_byte_as_bits[6:8], 2)]  # convert to bytes
        # Extract stream_length from the packet to determine the length

        if self.stream_length > 0:
            self.stream_id = self.packet_body[self.reader:self.reader+self.stream_length]
            self.reader += self.stream_length

        if self.offset_length > 0:
            self.offset = self.packet_body[self.reader:self.reader+self.offset_length]
            self.reader += self.offset_length

        if self.data_length_present:
            self.data_length = self.packet_body[self.reader:self.reader+2]
            self.data_length = processor_hex_to_int(self.data_length)
            self.reader += 2

        # all these numbers are little endian, so probably convert it :)

        # Now only the stream data is left

    def process(self):
        self.parse_frame_header()
        derived_shared_key = SessionInstance.get_instance().shared_key

        if self.data_length_present:
            # If the data length is present, then there might be an additional frame. So care must be taken when processing.
            ciphertext = self.packet_body[self.reader:self.reader+self.data_length]
            self.reader += self.data_length
        else:
            # Otherwise, the remainder of the packet is the data. So we must clear the packet body.
            ciphertext = self.packet_body[self.reader:]
            self.reader += len(ciphertext)
        print(len(ciphertext))
        # gcm_instance = AESGCM(key=derived_shared_key)
        print("Decrypting it... {}".format(ciphertext))
