from Processors.Processor import Processor


class WindowUpdateProcessor(Processor):
    stream_id = None    # 32 bits = 4 bytes
    byte_offset = None  # 64 bits = 8 bytes

    def my_frame(self):
        return self.packet_body[self.reader] == "04"

    def process(self):
        self.reader += 1

        self.stream_id = self.packet_body[self.reader:self.reader+4]
        self.reader += 4

        self.byte_offset = self.packet_body[self.reader:self.reader+8]
        self.reader += 8
