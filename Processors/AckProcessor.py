from Processors.Processor import Processor


class AckProcessor(Processor):
    packet_body = None
    reader = 0
    num_timestamps = 0
    largest_ack_size = None
    first_byte_as_bits = None
    first_ack_block_length = None
    num_blocks_present = None
    num_blocks = None

    largest_ack = None
    largest_ack_delta_time = None
    first_ack = None

    gap_to_next_block = None
    ack_block = None

    def my_frame(self):
        self.first_byte_as_bits = bin(int(self.packet_body[self.reader], base=16))[2:].zfill(8)  # pad to 8 bits. Remove leading 0b
        return self.first_byte_as_bits[0] == '0' and self.first_byte_as_bits[1] == '1'

    def process_header(self):
        largest_ack_sizes = [1, 2, 4, 6]    # in bytes
        self.largest_ack_size = largest_ack_sizes[int(self.first_byte_as_bits[4:6], 2)] # convert to largest ack size

        # self.num_blocks_present = self.first_byte_as_bits[2] == "1"

        first_ack_block_lengths = [1, 2, 4, 6]
        self.first_ack_block_length = first_ack_block_lengths[int(self.first_byte_as_bits[6:8], 2)]

    def process(self):
        self.process_header()
        self.reader += 1

        self.largest_ack = self.packet_body[self.reader:self.reader+self.largest_ack_size]
        self.reader += self.largest_ack_size

        self.largest_ack_delta_time = self.packet_body[self.reader:self.reader+2]
        self.reader += 2

        if self.num_blocks_present:
            self.num_blocks = self.packet_body[self.reader]
            self.num_blocks = int(self.num_blocks, 16) # convert to int
            self.reader += 1

        self.first_ack = self.packet_body[self.reader:self.reader+self.first_ack_block_length]
        self.reader += self.first_ack_block_length

        # print(self.num_blocks_present)
        # print(self.num_blocks)
        if self.num_blocks_present:
            self.gap_to_next_block = self.packet_body[self.reader]

            # Lets just skip all the ack block lengths
            self.reader += self.num_blocks

            # self.ack_block = self.packet_body[self.reader:self.reader+self.first_ack_block_length]
            # self.reader += self.first_ack_block_length

        try:
            self.num_timestamps = self.packet_body[self.reader]
            self.num_timestamps = int(self.num_timestamps, 16)
            self.reader += 1

            self.reader += 1
            self.reader += 4
            self.reader += self.num_timestamps * 3
        except IndexError:
            self.packet_body = []
