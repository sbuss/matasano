from hex_utils import bytes_to_hex
from hex_utils import hexxor


def xor_encrypt_string(str1, key_str):
    return hexxor(bytes_to_hex(str1), bytes_to_hex(key_str))
