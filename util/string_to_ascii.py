def string_to_ascii(value):
    """
    Not the best method name, but you can copy the value from a key in Wireshark
    And use this method to get the same value to use for Scapy.
    :param value:
    :return:
    """
    n = 2

    try:
        # Per two convert to hex
        value_per_two_characters = [value[i:i + n] for i in range(0, len(value), n)]
        # from hex convert to ascii
        ascii_values = [int(x, 16) for x in value_per_two_characters]

        # use ascii string
        converted_ascii_values = [chr(x) for x in ascii_values]

        # join to one string
        output = "".join(converted_ascii_values)
        return output
    except Exception:
        return ""
