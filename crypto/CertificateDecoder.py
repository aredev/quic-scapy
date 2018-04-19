from enum import Enum

# Implementation is not finished, as I don't think it is necessary

class EntryTypes(Enum):
    COMPRESSED = 1
    CACHED = 2
    COMMON = 3


def determine_entry_type(entry_type_byte):
    if entry_type_byte == 1:
        return EntryTypes.COMPRESSED
    elif entry_type_byte == 2:
        return EntryTypes.CACHED
    elif entry_type_byte == 3:
        return EntryTypes.COMMON
    else:
        raise Exception("Unknown entry type")


def decompress_chain(data):
    chain = []
    entries = []
    num_certs = 0

    for entry_type_byte in data:
        entry_type_byte = hex(entry_type_byte)
        if entry_type_byte == 0:
            break
            
        entry_type = determine_entry_type(entry_type_byte)
        num_certs += 1

        has_compressed_certificates = False

        if entry_type == EntryTypes.CACHED:
            raise Exception("Unexpected Cached Certificate")
        elif entry_type == EntryTypes.COMMON:
            # Also not really happening
            pass
        elif entry_type == EntryTypes.COMPRESSED:
            has_compressed_certificates = True
            chain.append({'entry': EntryTypes.COMPRESSED})

        # if has_compressed_certificates:
            # uncompressed_length =


n = 2
data = "0100bc03000078bb22517eb1dbc1cc002cb998b7183431cd59002c8398981851ca216e60392467286320058e721ee1c0504f6758591c949f5f022ba72d0c8c8d8c0c4d80d80894412c91b80629a8c51834a571f070390353415a7e515e66222c79b1f3f0fae697e69580d24a58666ab9a188811038f278b8916c3614321080b887d3d0c85ccf00080d0916cbc7cdb6ce5d65e9d69a75e588690247d119e95b73397827d8aa9d3c7b2685e7d5e10b22733fdf2b4cb966f5ec0cd7b97fee9deacb247e30ee369938c15ffaee2ac13a968e7957338ffc9456fdff2a709ecb55ddab6b0f3d3ea124796ca6c2d9d56ba6896c7d10a0e4eb7db76cc5d2fb8b7bdfb63cde6dfdc4a153dee5e78b4defae0574a55ddd147e309db359bfe29271e1e15da764cb7f9fdcac94fd88cd3b7d13c3dfad778fcc9cbad1caea4567a3def51605ab58c1ebfab776bf72bab92ce2dbdbf2996f057d6f184be67f7caa7b63e2c40f4f925e867fb9d0b1645f84c752c17de1429fb32f7bac8e7fcc53ec24a83d6f39ef4ae1d94b5670f57cfdf9b841355471d186eed5b17add9b92f67c2bfccbc4ccc8c0b8b8719b41e366f462175e3f69336d52d29df79d739ab1676ecaa9a3b3adfecffc8e92b054279b6c4b50d1f2b28b96fe19fdeff2e1"
data = [data[i:i+n] for i in range(0, len(data), n)]

decompress_chain(data)
