import re


def find_all_indexes_of_substring_in_string(data, needle):
    return [m.start() for m in re.finditer(needle, data)]
