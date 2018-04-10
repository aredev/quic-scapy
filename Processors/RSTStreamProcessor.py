from Processors.Processor import Processor


class RSTStreamProcessor(Processor):
    stream_id = None
    byte_offset = None
    error_code = None

    def my_frame(self):
        return self.packet_body[self.reader] == "01"

    def process(self):
        self.reader += 1

        self.stream_id = self.packet_body[self.reader:self.reader+4]
        self.reader += 4

        self.byte_offset = self.packet_body[self.reader:self.reader+8]
        self.reader += 8

        self.error_code = self.packet_body[self.reader:self.reader+4]
        self.reader += 4
