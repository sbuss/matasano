import math

from Crypto.Cipher.AES import AESCipher

from aes_utils import detect_block_cipher
from hex_utils import bytes_to_hex
from hex_utils import hex_to_bytes
from hex_utils import hex_to_int
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
    plaintext = a.decrypt(hex_to_bytes(hex_str))
    # remove the padding
    last_byte_int = hex_to_int(bytes_to_hex(plaintext[-1:]))
    if plaintext[-last_byte_int:] == plaintext[-1:] * last_byte_int:
        plaintext = plaintext[:-last_byte_int]
    return plaintext


def aes_cbc(hex_str, key, init_vector=None, blocksize=16):
    """Decrypt a hex_str encrypted with CBC mode.

    Args:
        hex_str: The encrypted string, in hex
        key: The key, in bytes
        init_vector: A vector of hex bytes, as long as the blocksize. If not
            supplied defaults to '00' * blocksize
        blocksize: The size of the encryption blocks. Should match the len
            of the key.
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


def aes_ecb_brute_byte(cipher_fn):
    """Discover the unknown_string in the cipher_fn.

    Relies on the ciper_fn to append an unknown string to the inputted
    plaintext.
    """
    # Discover block size
    blocksize = 0
    _s = "A"
    s = ""
    last_enc_len = len(cipher_fn(s))
    while blocksize == 0:
        s += _s
        enc_str = cipher_fn(s)
        # divide by two because bytes<->hex
        blocksize = (len(enc_str) - last_enc_len) / 2
    # Now we know the size of the unknown string being appended to our input
    len_unknown_msg = (len(enc_str) / 2) - (len(s) - 1) - blocksize

    if blocksize <= 1:
        raise ValueError("Blocksize is too small to work with.")
    # Ensure we're working with ECB
    if detect_block_cipher(cipher_fn) != 'ECB':
        raise ValueError("cipher_fn is not using ECB")

    def _get_block(ciphertext, blocknum):
        """Get the given block from the ciphertext"""
        start = blocksize * blocknum * 2
        end = start + blocksize * 2
        return ciphertext[start:end]

    def _get_dict_of_possible_bytes(prefix):
        """Build a dictionary of encrypted block -> byte."""
        possible_bytes = {}
        # start = (len(prefix) + 1 - blocksize) * 2
        # end = start + blocksize * 2
        for new_byte in (hex_to_bytes(int_to_hex(x)) for x in xrange(256)):
            key = "%s%s" % (prefix, new_byte)
            block = _get_block(cipher_fn(key), 0)
            possible_bytes[block] = new_byte
        return possible_bytes

    # Now decrypt every byte in the encrypted hex_str input
    plaintext = ''
    # Will have to decrypt every byte in the unknown str, which is as many
    # bytes as the result of cipher_fn on an empty str
    for byte_count in xrange(len_unknown_msg):
        # Block number is how many byte-blocks of size blocksize we've solved
        block_number = int(math.floor(byte_count / blocksize))
        # how many bytes don't we know yet?
        num_unknown_bytes = blocksize - (byte_count % blocksize)
        # Our base prefix should be the number of unknown bytes, minus 1
        # (minus 1 so we can solve that last byte)
        # This will be our plaintext input to the encryption oracle
        base_enc_block = 'A' * (num_unknown_bytes - 1)
        # The prefix, past the first block, does not contain the AAAs since
        # we need to look deeper into the unknown string.
        # For example, if our unknown str was
        #   "we all live in a yellow submarine"
        # Then the first block would be found by repeatedly encrypting
        #   "A" * num_unknown_bytes + plaintext
        #   (eg "AAwe all live i" would let us find "n")
        # But past the first block we need to look at the encrypted output
        # of the later blocks, which means we only need to offset the unknown
        # str by num_unknown_bytes and look at the desired block.
        # For example, say we now know "we all live in a", now we need to find
        # " ", but we can only find that by making " " the last byte of the
        # second block, so we give "A" * 15 as our plaintext, which makes
        # the cipher_fn see this as the plaintext:
        #   'AAAAAAAAAAAAAAA' + unknown_str =
        #   'AAAAAAAAAAAAAAAw' | 'e all live in aX'  (where X is unknown)
        # So we find X = " ", as before, decrement num_unknown_bytes, and
        # continue solving.
        prefix = (base_enc_block + plaintext)[-(blocksize-1):]
        enc_blocks_dict = _get_dict_of_possible_bytes(prefix)
        plaintext += (
            enc_blocks_dict[
                _get_block(cipher_fn(base_enc_block), block_number)])
    return plaintext
