from collections import Counter
from collections import OrderedDict
from urllib import urlencode
from urlparse import parse_qs

from Crypto.Random import get_random_bytes

from aes_utils import get_blocksize
from decrypt import aes_ecb as decrypt_aes_ecb
from encrypt import aes_ecb as encrypt_aes_ecb
from hex_utils import pkcs7_padding
from iter_utils import group


def profile_for(email):
    return OrderedDict([
        ('email', email),
        ('uid', 10),
        ('role', 'user'),
    ])


def encode_profile(profile):
    return urlencode(profile)


def decode_profile(kv_str):
    parsed_qs = parse_qs(kv_str)
    if any(len(item) != 1 for item in parsed_qs.values()):
        raise ValueError("Repeated keys are not allowed, cheater!")
    return OrderedDict([
        ('email', parsed_qs['email'][0]),
        ('uid', int(parsed_qs['uid'][0])),
        ('role', parsed_qs['role'][0]),
    ])


profile_key = get_random_bytes(16)


def encrypted_profile_for(email):
    return encrypt_aes_ecb(
        pkcs7_padding(
            encode_profile(profile_for(email)), 16),
        profile_key)


def decrypted_profile(enc_str):
    return decode_profile(decrypt_aes_ecb(enc_str, profile_key))


def get_admin_user():
    # first find the blocksize
    blocksize = get_blocksize(encrypted_profile_for)

    # Now find the block border so we can get the encrypted admin block
    admin_str = pkcs7_padding("admin", blocksize)
    # Only loop as many times as the blocksize, to avoid possible failure mode
    # with an infinite loop
    block_border = -1
    for i in xrange(blocksize):
        email = "%s%s" % ('A' * i, admin_str * 3)
        blocks = group(encrypted_profile_for(email), blocksize*2)
        if any(value == 3 for value in dict(Counter(blocks)).values()):
            block_border = i
            break
    if block_border == -1:
        raise ValueError(
            "The blocksize must be wrong, we didn't find the border.")
