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
