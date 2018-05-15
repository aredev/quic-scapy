import struct


class DynamicCHLOPacket:

    __tags: []
    __body = b""
    __offset = 0

    def __init__(self, tags):
        self.__tags = tags

    def __write_to_body(self, data):
        self.__body += bytes.fromhex(data)

    def build_body(self):
        len_of_tags = len(self.__tags)
        len_of_tags = struct.pack('<h', len_of_tags).hex()

        self.__write_to_body("80")  # Crypto
        self.__write_to_body("01")
        self.__write_to_body("43484c4f")    # Fixed CHLO  tag
        self.__write_to_body(len_of_tags)
        self.__write_to_body("00")
        self.__write_to_body("00")

        for index, tag in enumerate(self.__tags):
            tag_as_hex = ''.join(r'{0:x}'.format(ord(c)) for c in tag['name']).ljust(8, '0')
            length_as_hex = struct.pack('<I', self.__offset + int(len(tag['value'])/int(2))).hex()
            self.__offset += int(len(tag['value'])/2)

            self.__body += bytes.fromhex(tag_as_hex)
            self.__write_to_body(length_as_hex)

        for tag in self.__tags:
            self.__write_to_body(tag['value'])

        return self.__body.hex()
