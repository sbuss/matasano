import base64
import binascii


def hex_to_bytes(hex_str):
    return binascii.a2b_hex(hex_str)


def hex_to_b64(hex_str):
    return base64.b64encode(hex_to_bytes(hex_str))
