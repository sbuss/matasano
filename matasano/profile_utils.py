from collections import OrderedDict
from urllib import urlencode
from urlparse import parse_qs

from Crypto.Random import get_random_bytes

from decrypt import aes_ecb as decrypt_aes_ecb
from encrypt import aes_ecb as encrypt_aes_ecb
from hex_utils import pkcs7_padding


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
