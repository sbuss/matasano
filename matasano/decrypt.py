from Crypto.Cipher.AES import AESCipher

from hex_utils import bytes_to_hex
from hex_utils import hex_to_bytes
from hex_utils import hexxor


def xor(hex_str, key):
    """Decrypt a hex str encrypted with an simple XOR cipher.

    Args:
        hex_str: The encrypted string, in hex
        key: The key, in bytes
    Returns the decrypted string, in bytes
    """
    return hex_to_bytes(hexxor(hex_str, bytes_to_hex(key)))


def aes_ecb(hex_str, key):
    """Decrypt a hex str encrypted with AES-128-ECB

    Args:
        hex_str: The encrypted string, in hex
        key: The key, in bytes
    Returns the decrypted string, in bytes
    """
    a = AESCipher(key)
    return a.decrypt(hex_to_bytes(hex_str))
