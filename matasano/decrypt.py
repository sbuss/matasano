from Crypto.Cipher.AES import AESCipher

from hex_utils import hex_to_bytes


def decrypt_aes(hex_str, key):
    a = AESCipher(key)
    return a.decrypt(hex_to_bytes(hex_str))
