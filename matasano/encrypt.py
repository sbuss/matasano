from Crypto.Cipher.AES import AESCipher

from hex_utils import bytes_to_hex
from hex_utils import hex_to_bytes
from hex_utils import hexxor
from hex_utils import int_to_hex
from hex_utils import pkcs7_padding
from iter_utils import yield_blocks


def xor_encrypt_string(str1, key_str):
    return hexxor(bytes_to_hex(str1), bytes_to_hex(key_str))


def aes_ecb(raw_str, key):
    """Encrypt the raw_str with AES ECB mode, and return a hex str."""
    a = AESCipher(key)
    return bytes_to_hex(a.encrypt(raw_str))


def aes_cbc(raw_str, key, init_vector=None, blocksize=16):
    """Encrypt a string in AES CBC mode

    Args:
        raw_str: The string to encrypt
        key: The key to use, in bytes
        init_vector: A vector of hex bytes, as long as the blocksize. If not
            supplied defaults to '00' * blocksize
        blocksize: The size of the encryption blocks. Should match the len
            of the key.
    Returns an encrypted string, in hex.
    """
    assert blocksize == len(key)
    enc_str = ""
    if not init_vector:
        init_vector = int_to_hex(0) * blocksize
    last_enc_block = init_vector
    hex_str = bytes_to_hex(raw_str)
    for block in yield_blocks(
            pkcs7_padding(hex_str, blocksize*2), blocksize):
        assert len(block) == len(last_enc_block)
        xor_block = hexxor(last_enc_block, block)
        last_enc_block = aes_ecb(hex_to_bytes(xor_block), key)
        enc_str += last_enc_block
    return enc_str
