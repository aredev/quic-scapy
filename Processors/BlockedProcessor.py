from Processors.Processor import Processor


class BlockedProcessor(Processor):
    stream_id = None    # 32 bits = 4 bytes

    def my_frame(self):
        return self.packet_body[self.reader] == "05"

    def process(self):
        self.reader += 1

        self.stream_id = self.packet_body[self.reader:self.reader+4]
        self.reader += 4
