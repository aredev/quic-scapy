import json

from Processors.ProcessedFramesInstance import ProcessedFramesInstance
from Processors.Processor import Processor
from Processors.SHLOPacketProcessor import SHLOPacketProcessor
from events.Exceptions import NotSHLOButHtmlException, NotHtmlNorSHLOException, NotSHLOButCloseException
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
    status = ""

    def my_frame(self):
        self.first_byte_as_bits = bin(int(self.packet_body[self.reader], base=16))[2:].zfill(8)
        return self.first_byte_as_bits[0] == "1"

    def process(self):
        """
        Assumption, the stream frame is last. FIXME
        :return:
        """
        # Add stream Id == 1 check
        # Set the stream Id. It starts after the header (byte 27), after the byte frame type (28).
        try:
            was_shlo = SHLOPacketProcessor(self.packet_body).parse()
            SessionInstance.get_instance().shlo_received = was_shlo
            if was_shlo:
                self.status = "shlo"
            else:
                self.status = "unknown"
        except NotSHLOButHtmlException as err:
            # If we catch the exception, then it is not a SHLO (Stream ID != 1)
            self.status = "http"
        except NotHtmlNorSHLOException as err:
            # We don't know what it is.
            self.status = "unknown"
        except NotSHLOButCloseException as err:
            self.status = "close"

    def result(self):
        """
        Because everything is captured as ciphertext, there isn't anything left.
        :return:
        """
        return []
