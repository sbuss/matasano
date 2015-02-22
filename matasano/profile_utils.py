from collections import OrderedDict
from urllib import urlencode
from urlparse import parse_qs


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
