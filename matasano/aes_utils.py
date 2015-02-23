from collections import Counter

from Crypto.Random import get_random_bytes
from Crypto.Random import random

from hex_utils import b64_to_hex
from hex_utils import bytes_to_hex
from hex_utils import hex_to_bytes
from hex_utils import pkcs7_padding
from iter_utils import group


def random_key(blocksize=16):
    """Get a random key, in bytes, of len blocksize."""
    return get_random_bytes(blocksize)


def encryption_oracle(plaintext):
    """Encrypt the plaintext with a random key.

    Args:
        plaintext: The string to encrypt.
    """
    from .encrypt import aes_ecb
    from .encrypt import aes_cbc
    blocksize = 16
    key = random_key(blocksize)
    num_prepend_bytes = random.randint(1, 5)
    num_append_bytes = random.randint(1, 5)
    padded_plaintext = pkcs7_padding(
        get_random_bytes(num_prepend_bytes) +
        plaintext +
        get_random_bytes(num_append_bytes),
        blocksize)
    if random.randint(1, 2) == 1:
        # aes_ecb
        return aes_ecb(padded_plaintext, key)
    else:
        # cbc mode
        iv = bytes_to_hex(get_random_bytes(blocksize))
        return aes_cbc(
            padded_plaintext, key, init_vector=iv, blocksize=blocksize)


def detect_block_cipher(cipher_fn):
    """Detect if the cipher_fn is using ECB or CBC mode."""
    blocksize = 16
    # Use a string that will cause ECB to duplicate blocks
    s = 'X' * 128
    cipher_result = cipher_fn(s)
    blocks = group(cipher_result, blocksize * 2)
    if any(count > 1 for count in dict(Counter(blocks)).values()):
        return 'ECB'
    return 'CBC'


consistent_ecb_oracle_key = get_random_bytes(16)


def consistent_ecb_oracle(plaintext):
    from .encrypt import aes_ecb
    blocksize = 16
    key = consistent_ecb_oracle_key
    # num_prepend_bytes = random.randint(1, 5)
    # num_append_bytes = random.randint(1, 5)
    plaintext = plaintext + hex_to_bytes(b64_to_hex(
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
        "YnkK"))
    padded_plaintext = pkcs7_padding(
        # get_random_bytes(num_prepend_bytes) +
        plaintext,  # +
        # get_random_bytes(num_append_bytes),
        blocksize)
    return aes_ecb(padded_plaintext, key)


def get_blocksize(cipher_fn):
    """Get the blocksize, and the plaintext input size that revealed it."""
    blocksize = 0
    s = ""
    base_len = len(cipher_fn(s))
    while blocksize == 0:
        s += "A"
        blocksize = len(cipher_fn(s)) - base_len
    blocksize /= 2
    return (blocksize, len(s))
