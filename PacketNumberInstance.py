import struct


class PacketNumberInstance:

    __instance = None
    next_packet_number = 1  # This is represented as 00 01, 00 02, 00 03, ... and returned as int
    highest_received_packet_number = "01"

    @staticmethod
    def get_instance():
        if PacketNumberInstance.__instance is None:
            return PacketNumberInstance()
        else:
            return PacketNumberInstance.__instance

    def __init__(self):
        if PacketNumberInstance.__instance is not None:
            raise Exception("Singleton bla")
        else:
            PacketNumberInstance.__instance = self

    def get_next_packet_number(self):
        """
        Retrieve the next packet number which needs to be used by an outgoing packet
        :return:
        """
        # Retrieve the current next number, as regular int
        use = self.next_packet_number

        # convert it to bytes
        use_big_end = struct.pack('>h', use)
        # back to an int
        use_big_end_int = int.from_bytes(use_big_end, byteorder='little')

        # increment the normal int
        self.next_packet_number += 1
        return use_big_end_int

    def update_highest_received_packet_number(self, new_highest: int):
        if new_highest > int(self.highest_received_packet_number):
            self.highest_received_packet_number = new_highest

    def get_highest_received_packet_number(self):
        return self.highest_received_packet_number

    def reset(self):
        self.next_packet_number = 1
        self.highest_received_packet_number = "01"
