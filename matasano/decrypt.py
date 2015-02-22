from Crypto.Cipher.AES import AESCipher

from aes_utils import detect_block_cipher
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

    if blocksize <= 1:
        raise ValueError("Blocksize is too small to work with.")
    # Ensure we're working with ECB
    if detect_block_cipher(cipher_fn) != 'ECB':
        raise ValueError("cipher_fn is not using ECB")

    def _get_dict_of_possible_bytes(prefix):
        possible_bytes = {}
        start = (len(prefix) + 1 - blocksize) * 2
        end = start + blocksize * 2
        for new_byte in (hex_to_bytes(int_to_hex(x)) for x in xrange(256)):
            key = "%s%s" % (prefix, new_byte)
            possible_bytes[cipher_fn(key)[start:end]] = new_byte
        return possible_bytes

    # Now decrypt every byte in the encrypted hex_str input
    plaintext = ''
    # Will have to decrypt every byte in the unknown str, which is as many
    # bytes as the result of cipher_fn on an empty str
    for byte_count in xrange(len(cipher_fn("")) / 2):
        # Block number is how many byte-blocks of size blocksize we've solved
        # block_number = int(math.floor(byte_count / blocksize))
        # how many bytes don't we know yet?
        num_unknown_bytes = blocksize - (byte_count % blocksize)
        # Our base prefix should be the number of unknown bytes, minus 1
        # (minus 1 so we can solve that last byte)
        base_enc_block = 'A' * (num_unknown_bytes - 1)
        prefix = base_enc_block + plaintext
        enc_blocks_dict = _get_dict_of_possible_bytes(prefix)
        start = (len(prefix) + 1 - blocksize) * 2
        end = start + blocksize * 2
        plaintext += (
            enc_blocks_dict[cipher_fn(base_enc_block)[start:end]])
        # TODO How do I handle blocks after the first?
    return plaintext
