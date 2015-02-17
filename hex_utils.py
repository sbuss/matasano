import base64
import binascii
import math

from Crypto.Util.strxor import strxor


def hex_to_bytes(hex_str):
    """Convert a hex string to bytes."""
    return binascii.a2b_hex(hex_str)


def bytes_to_hex(hex_bytes):
    return binascii.b2a_hex(hex_bytes)


def hex_to_b64(hex_str):
    """Convert a hex string to a base64 string.
    Args:
        hex_str: The hex string you want to convert. If this is already a hex
            bytes array it'll fail, since python can't really tell the
            difference.
    """
    return base64.b64encode(hex_to_bytes(hex_str))


def hex_to_int(hex_str):
    """Convert a hex string to an int"""
    return int(hex_str, 16)


def int_to_hex(hex_int):
    """Convert an integer into a hex string"""
    if hex_int < 0 or hex_int > 255:
        raise ValueError(
            "Value (%s) must be between 0 and 255, inclusive" % hex_int)
    return format(hex_int, 'x').zfill(2)


def _list_of_hex_strs(hex_str):
    return [bytes_to_hex(byte) for byte in hex_to_bytes(hex_str)]


def hexxor(hex_str1, hex_str2):
    """XOR two hex strings

    Whichever hex str is shorter will be cycled until it's the length of the
    longer hex string.
    """
    def _pad(s1, s2):
        multiplier = int(math.ceil(len(s2) / len(s1))) + 1
        s1 = (s1 * multiplier)[:len(s2)]
        return s1

    if len(hex_str1) < len(hex_str2):
        hex_str1 = _pad(hex_str1, hex_str2)
    elif len(hex_str1) > len(hex_str2):
        hex_str2 = _pad(hex_str2, hex_str1)
    return bytes_to_hex(strxor(hex_to_bytes(hex_str1), hex_to_bytes(hex_str2)))
