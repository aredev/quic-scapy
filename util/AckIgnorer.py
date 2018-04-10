from util.packet_to_hex import extract_from_packet_as_bytes


def is_ack_frame(possible_ack_frame):
    """
    Checks if a frame is an ack frame, by checking the following conditions
        1. First bit == 0
        2. Second bit == 1
    :param possible_ack_frame:
    :return: boolean
    """
    return extract_from_packet_as_bytes(possible_ack_frame, end=2) == "01"


def ignore_ack_frame(ack_frame):
    """
    We do not really need the Ack frame, so we can ignore it I guess.
    For this we
    :return:
    """

    print(ack_frame)
    if is_ack_frame(ack_frame):
        # Retrieve the num timestamp
        num_timestamp = 100

        # Use this to skip the 3 bytes.

    else:
        raise Exception("Not Ack Frame exception.")
