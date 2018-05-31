def processor_hex_to_int(number):
    """
    Receives an array of strings of hexes
    :param number:
    :return: number
    """
    if number == "":
        return 0
    else:
        return int("".join(number[::-1]), 16)
