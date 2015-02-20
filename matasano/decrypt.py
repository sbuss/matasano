from Crypto.Cipher.AES import AESCipher

from hex_utils import hex_to_bytes


def aes(hex_str, key):
    """Decrypt a hex str encrypted with AES-128-ECB

    Args:
        hex_str: The encrypted string, in hex
        key: The key, in bytes
    Returns the decrypted string, in bytes
    """
    a = AESCipher(key)
    return a.decrypt(hex_to_bytes(hex_str))
