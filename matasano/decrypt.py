from Crypto.Cipher.AES import AESCipher

from hex_utils import bytes_to_hex
from hex_utils import hex_to_bytes
from hex_utils import hexxor
from hex_utils import int_to_hex
from iter_utils import yield_blocks


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


def aes_ecb_cbc(hex_str, key, init_vector=None, blocksize=16):
    """Decrypt a hex_str encrypted with CBC mode.

    Args:
        hex_str: The encrypted string, in hex
        key: The key, in bytes
    Returns the decrypted string, in bytes
    """
    raw_str = ""
    if not init_vector:
        init_vector = int_to_hex(0) * blocksize
    last_block = init_vector
    for block in yield_blocks(hex_str, blocksize):
        assert len(block) == len(last_block)
        raw_block = bytes_to_hex(aes_ecb(block, key))
        raw_str += hexxor(raw_block, last_block)
        last_block = block
    return hex_to_bytes(raw_str)
