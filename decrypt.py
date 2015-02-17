from collections import namedtuple
import random

from hex_utils import hamming_distance
from hex_utils import hex_to_bytes
from hex_utils import hexxor
from hex_utils import int_to_hex
from score_english import sentence_is_english


EncryptedString = namedtuple(
    "EncryptedString", ["english_score", "encrypted_string", "key", "string"])


def single_byte_xor(hex_string, num_candidates=1):
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
            key=xor_hex,
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
            candidate = single_byte_xor(l, 1)[0]
            candidates.append(candidate)
    return sorted(candidates)[0]


KeysizeCandidate = namedtuple("KeysizeCandidate", ["score", "keysize"])


def _get_keysize_candidates(hex_str, keysize_range):
    keysize_candidates = []
    for keysize in xrange(*keysize_range):
        # because keysize is bytes, and we're operating on hex values, we
        # need to always look at two characters at a time, so double the
        # keysize
        keysize_byte = keysize * 2
        str1 = hex_str[:keysize_byte]
        str2 = hex_str[keysize_byte:keysize_byte+keysize_byte]
        distance = hamming_distance(str1, str2)
        keysize_candidates.append(
            KeysizeCandidate(score=distance/keysize, keysize=keysize))
    return sorted(keysize_candidates)


def decrypt_repeated_key_xor(hex_str, keysize_range=(2, 40)):
    """Break repeated-key-xor encryption.

    Args:
        hex_string: A hex string that has been encrypted with repeated key xor
            of an unknown key
        keysize_range: The range of keysizes, in bytes, to brute force.
    Returns an EncryptedString namedtuple
    """
    # Find a few keysizes with minimal edit distance
    keysize_candidates = _get_keysize_candidates(hex_str, keysize_range)[:5]
