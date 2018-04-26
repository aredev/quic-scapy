import json

from Processors.ProcessedFramesInstance import ProcessedFramesInstance
from Processors.Processor import Processor
from Processors.SHLOPacketProcessor import SHLOPacketProcessor
from connection.ConnectionInstance import ConnectionInstance, ConnectionEndpoint
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

    def process(self):
        """
        Assumption, the stream frame is last. FIXME
        :return:
        """
        if not SessionInstance.get_instance().shlo_received:
            print("Processing SHLO")
            SHLOPacketProcessor(self.packet_body).parse()
            SessionInstance.get_instance().shlo_received = True
        else:
            print("Perform other post processing on this packet {}".format(self.packet_body))

    def result(self):
        """
        Because everything is captured as ciphertext, there isn't anything left.
        :return:
        """
        return []
