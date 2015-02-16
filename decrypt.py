from collections import namedtuple

from hex_utils import hex_to_bytes
from hex_utils import hexxor
from hex_utils import int_to_hex
from score_english import sentence_is_english


EncryptedString = namedtuple(
    "EncryptedString", ["encrypted_string", "key", "string", "english_score"])


def single_byte_xor(hex_string, num_candidates=1):
    """Given an encoded hex string, find the byte with which is was xored.

    Args:
        hex_string: The hex string to decrypt.
        num_candidates: How many of the top english candidates to return.
    Returns the `num_candidates` most likely english sentences
    """
    candidates = []
    for byte in range(256):
        # First pad out the xor byte to the length of the string
        hex_xor_key = int_to_hex(byte) * len(hex_string)
        # Then xor the stuff
        xor_hex = hexxor(hex_string, hex_xor_key)
        # Then score it and put it in the canddiate list
        candidate = hex_to_bytes(xor_hex)
        candidates.append(EncryptedString(
            encrypted_string=hex_string,
            english_score=sentence_is_english(candidate),
            key=xor_hex,
            string=candidate))
    sc = sorted(candidates,
                key=lambda candidate: candidate.english_score)[:num_candidates]
    return sc


def find_encrypted_hex_string(infile):
    candidates = []
    with open(infile, 'r') as f:
        for line in f:
            l = line.strip()
            candidate = single_byte_xor(l, 1)[0]
            candidates.append((l, candidate))
    return sorted(candidates,
                  key=lambda candidate: candidate[1].english_score)[0]
