from Crypto.Cipher.AES import AESCipher

from hex_utils import bytes_to_hex
from hex_utils import hexxor


def xor_encrypt_string(str1, key_str):
    return hexxor(bytes_to_hex(str1), bytes_to_hex(key_str))


def aes_ecb(raw_str, key):
    """Encrypt the raw_str with AES ECB mode, and return a hex str."""
    a = AESCipher(key)
    return bytes_to_hex(a.encrypt(raw_str))
