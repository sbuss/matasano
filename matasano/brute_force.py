from itertools import combinations
from collections import Counter
from collections import namedtuple
from itertools import starmap
from operator import mul
import random

from hex_utils import hamming_distance
from hex_utils import hex_to_bytes
from hex_utils import hexxor
from hex_utils import int_to_hex
from iter_utils import group
from iter_utils import transpose_blocks
from iter_utils import yield_blocks
from score_english import sentence_is_english


EncryptedString = namedtuple(
    "EncryptedString", ["english_score", "encrypted_string", "key", "string"])


def crack_single_byte_xor(hex_string, num_candidates=1):
    """Given an encoded hex string, find the byte with which is was xored.

    Args:
        hex_string: The hex string to decrypt.
        num_candidates: How many of the top english candidates to return.
    Returns the `num_candidates` most likely english sentences
    """
    candidates = []
    r = range(256)
    random.shuffle(r)
    for byte in r:
        # First pad out the xor byte to the length of the string
        hex_xor_key = int_to_hex(byte)
        # Then xor the stuff
        xor_hex = hexxor(hex_string, hex_xor_key)
        # Then score it and put it in the canddiate list
        candidate = hex_to_bytes(xor_hex)
        candidates.append(EncryptedString(
            encrypted_string=hex_string,
            english_score=sentence_is_english(candidate),
            key=hex_xor_key,
            string=candidate))
    sc = sorted(candidates)[:num_candidates]
    return sc


def find_encrypted_hex_string(infile):
    """Find the encrypted string and its key in an input file.

    Args:
        infile: The input file
    Returns an EncryptedString namedtuple, which has the encrypted string,
    the decrypted string, the encryption key, and it's probability of being
    english.

    The input file has a single encrypted string (encrypted via simple xor)
    and a bunch of other random data. All strings are just hex strings.
    """
    candidates = []
    with open(infile, 'r') as f:
        for line in f:
            l = line.strip()
            candidate = crack_single_byte_xor(l, 1)[0]
            candidates.append(candidate)
    return sorted(candidates)[0]


KeysizeCandidate = namedtuple("KeysizeCandidate", ["score", "keysize"])


def _get_keysize_candidates(hex_str, keysize_range):
    keysize_candidates = []
    for keysize in xrange(*keysize_range):
        # because keysize is bytes, and we're operating on hex values, we
        # need to always look at two characters at a time, so double the
        # keysize
        keysize_bytes = keysize * 2
        # Bail out if we don't have enough data to compute a key
        num_blocks = 4
        if keysize_bytes * num_blocks > len(hex_str):
            break
        # Break the string up into blocks, and get the first num_blocks
        by = yield_blocks(hex_str, keysize)
        blocks = [by.next() for x in range(num_blocks)]
        # Apply hamming distance to every combination of blocks
        distances = list(starmap(hamming_distance, combinations(blocks, 2)))
        # Then average the distances
        avg_distance = sum(distances) * 1.0 / len(distances)
        # ...and normalize on the key size
        normalized_distance = avg_distance / keysize
        keysize_candidates.append(
            KeysizeCandidate(score=normalized_distance, keysize=keysize))
    return sorted(keysize_candidates)


def crack_repeated_key_xor(hex_str, keysize_range=(2, 40)):
    """Break repeated-key-xor encryption.

    Args:
        hex_string: A hex string that has been encrypted with repeated key xor
            of an unknown key
        keysize_range: The range of keysizes, in bytes, to brute force.
    Returns an EncryptedString namedtuple
    """
    # Find a few keysizes with minimal edit distance
    keysize_candidates = _get_keysize_candidates(hex_str, keysize_range)[:10]
    key_candidates = []
    for candidate in keysize_candidates:
        blocks = transpose_blocks(yield_blocks(hex_str, candidate.keysize))
        keys = []
        score = 0.0
        for block in blocks:
            decrypted_strs = crack_single_byte_xor(block, 5)
            decrypted_str = decrypted_strs[0]
            keys.append(decrypted_str.key)
            score += decrypted_str.english_score / (candidate.keysize * 2)
        key = "".join(keys)
        english_str = hex_to_bytes(hexxor(hex_str, key))
        key_candidates.append(
            (sentence_is_english(english_str), score, key, candidate.keysize,
             english_str))
    return sorted(key_candidates)


def find_aes_encrypted_hex_string(infile):
    """Find the string encrypted with AES ECB mode in a given input file.

    Args:
        infile: The path to the file containing hex-encoded strings.
    Returns a list of (score, candidate line) tuples that have duplicated
        16-byte blocks.  AES-ECB is deterministic and will always produce the
        same 16-byte encrypted block for the same 16-byte plaintext.
    """
    candidates = []
    with open(infile, 'r') as f:
        for line in f:
            l = line.strip()
            blocks = group(l, 32)
            num_repeats = dict(Counter(blocks))
            # make the score the product of number of repeats
            candidates.append((reduce(mul, num_repeats.values()), l))
    return sorted(
        filter(lambda candidate: candidate[0] > 1, candidates), reverse=True)
