import base64
import binascii


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
    return format(hex_int, 'x').zfill(2)


def _list_of_hex_strs(hex_str):
    return [bytes_to_hex(byte) for byte in hex_to_bytes(hex_str)]


def hexxor(hex_str1, hex_str2):
    def _ints(hex_str):
        return [hex_to_int(hex_bit)
                for hex_bit in _list_of_hex_strs(hex_str)]
    hex1_ints = _ints(hex_str1)
    hex2_ints = _ints(hex_str2)
    xor_ints = [hex1 ^ hex2 for (hex1, hex2) in zip(hex1_ints, hex2_ints)]
    return "".join(int_to_hex(xor) for xor in xor_ints)
