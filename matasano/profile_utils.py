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
    blocksize, len_plaintext = get_blocksize(encrypted_profile_for)

    # Now find the block border so we can get the encrypted admin block
    # admin_str = pkcs7_padding("admin", blocksize)
    admin_str = "admin" + ((blocksize - 5) * " ")
    # Only loop as many times as the blocksize, to avoid possible failure mode
    # with an infinite loop
    block_border = -1
    for i in xrange(blocksize):
        email = "%s%s" % ('A' * i, admin_str * 3)
        blocks = group(encrypted_profile_for(email), blocksize*2)
        counts = Counter(blocks)
        if counts.most_common(1)[0][1] == 3:
            block_border = i
            admin_block = counts.most_common(1)[0][0]
            break
    admin_block = ''.join(admin_block)
    if block_border == -1:
        raise ValueError(
            "The blocksize must be wrong, we didn't find the border.")
    # Now we know what len of email input will push a payload to its own block
    # and the encrypted block of our admin payload, which we'll append to the
    # end of the encrypted str.

    # We know that the email len which grows the encrypted_str is len_plaintext
    # from finding the blocksize earlier. We also know that &role=user is at
    # the end of the encoded profile. So just add three more bytes to get all
    # of "user" in its own block, and replace that block with our admin block
    enc_str = encrypted_profile_for('A' * (len_plaintext + 3))
    return decrypted_profile(enc_str[:-blocksize*2] + admin_block)
