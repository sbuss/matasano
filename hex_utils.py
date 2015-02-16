import base64
import binascii


def hex_to_bytes(hex_str):
    """Convert a hex string to bytes."""
    return binascii.a2b_hex(hex_str)


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
    return format(hex_int, 'x')


def hexxor(hex_str1, hex_str2):
    hex1 = hex_to_int(hex_str1)
    hex2 = hex_to_int(hex_str2)
    xor = hex1 ^ hex2
    return int_to_hex(xor)
