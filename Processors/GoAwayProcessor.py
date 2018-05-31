from Processors.Processor import Processor
from util.processor_hex_number_to_int import processor_hex_to_int


class GoAwayProcessor(Processor):
    error_code = None
    last_good_stream_id = 0
    reason_phrase_length = None
    reason_phrase = None

    def my_frame(self):
        return self.packet_body[self.reader] == "03"

    def process(self):
        self.reader += 1

        self.error_code = self.packet_body[self.reader:self.reader+4]
        self.reader += 4

        self.last_good_stream_id = self.packet_body[self.reader:self.reader+4]
        self.reader += 4

        self.reason_phrase_length = self.packet_body[self.reader:self.reader+2]
        self.reader += 2

        # convert the phrase length to an int
        if len(self.reason_phrase_length) > 0:
            self.reason_phrase_length = processor_hex_to_int(self.reason_phrase_length)

            self.reason_phrase = self.packet_body[self.reader:self.reader+self.reason_phrase_length]
            self.reader += self.reason_phrase_length
