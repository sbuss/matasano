import base64
import binascii


def hex_to_b64(hex_str):
    return base64.b64encode(binascii.a2b_hex(hex_str))
