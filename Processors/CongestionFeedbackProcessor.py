from Processors.Processor import Processor


class CongestionFeedbackProcessor(Processor):
    def my_frame(self):
        """
        First three bits should be 001
        :return:
        """
        first_byte_as_bits = bin(int(self.packet_body[self.reader], base=16))[2:].zfill(8)
        return first_byte_as_bits[0:3] == "001"

    def process(self):
        """
        Experimental frame, currently not used
        :return:
        """
        self.reader += 1
