def extract_from_packet(x, start=0, end=0):
    """
    Extract from the packet from index starting at start, until index ending at end
    Return it in the wireshark format. Such that it will be accepted by the FNV128A hash.
    :param start:
    :param end:
    :param x:
    :return:
    """
    x = bytes(x)
    l = len(x)
    i = start
    body = []

    if end == 0:
        end = l

    while i < end:
        for j in range(16):
            if i + j < end:
                body.append("%02X" % x[i + j])
                # print("%02X" % x[i + j], end=" ")
        i += 16
    return body


def extract_from_packet_as_bytestring(x, start=0, end=0):
    as_array = extract_from_packet(x, start, end)
    return "".join(as_array)
