from functools import partial
import random
from unittest import TestCase

from mock import patch

from ..aes_utils import consistent_ecb_oracle
from ..aes_utils import detect_block_cipher
from ..aes_utils import encryption_oracle
from ..decrypt import aes_ecb as decrypt_aes_ecb
from ..decrypt import aes_ecb_brute_byte
from ..decrypt import aes_cbc as decrypt_aes_cbc
from ..encrypt import aes_ecb as encrypt_aes_ecb
from ..encrypt import aes_cbc as encrypt_aes_cbc
from ..file_utils import b64_file_to_hex_str
from ..hex_utils import b64_to_hex
from ..hex_utils import bytes_to_hex
from ..hex_utils import hex_to_bytes
from ..hex_utils import int_to_hex
from ..hex_utils import pkcs7_padding
from ..profile_utils import decode_profile
from ..profile_utils import encode_profile
from ..profile_utils import profile_for


class TestSet2(TestCase):
    def test_challenge9_pkcs7_padding(self):
        s = "YELLOW SUBMARINE"
        pad_20 = pkcs7_padding(s, 20)
        self.assertEqual(pad_20[:16], s)
        self.assertEqual(pad_20[16:], "\x04" * 4)
        pad_24 = pkcs7_padding(s, 24)
        self.assertEqual(pad_24[:16], s)
        self.assertEqual(pad_24[16:], "\x08" * 8)
        pad_5 = pkcs7_padding(s, 5)
        self.assertEqual(pad_5[:16], s)
        self.assertEqual(pad_5[16:], "\x04" * 4)
        self.assertRaises(ValueError, pkcs7_padding, s, 1024)
        pad_0 = pkcs7_padding(s, len(s))
        self.assertEqual(len(s), len(pad_0))

    def test_challenge10_cbc(self):
        input_file = "matasano/tests/input_files/2.10.txt"
        hex_str = b64_file_to_hex_str(input_file)
        key = "YELLOW SUBMARINE"
        blocksize = 16
        iv = int_to_hex(0) * blocksize
        raw_file = decrypt_aes_cbc(
            hex_str, key=key, init_vector=iv, blocksize=blocksize)
        self.assertIn("Play that funky music white boy", raw_file)

    def test_challenge11_oracle(self):
        self.assertEqual(
            detect_block_cipher(partial(encrypt_aes_ecb, key='a'*16)), 'ECB')
        self.assertEqual(
            detect_block_cipher(partial(encrypt_aes_cbc, key='a'*16)), 'CBC')

        def _get_mock_randint(ecb=False):
            def _mock_randint(a, b):
                if a == 1 and b == 5:
                    return random.randint(a, b)
                else:
                    if ecb:
                        return 1
                    return 2
            return _mock_randint

        with patch('matasano.aes_utils.random.randint',
                   side_effect=_get_mock_randint(ecb=True)):
            self.assertEqual(detect_block_cipher(encryption_oracle), 'ECB')
        with patch('matasano.aes_utils.random.randint',
                   side_effect=_get_mock_randint(ecb=False)):
            self.assertEqual(detect_block_cipher(encryption_oracle), 'CBC')

    def test_challenge12_brute_ecb(self):
        unknown_msg = (
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
            "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
            "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
            "YnkK")
        self.assertEqual(
            aes_ecb_brute_byte(consistent_ecb_oracle),
            hex_to_bytes(b64_to_hex(unknown_msg)))


class TestECB(TestCase):
    def test_encrypt_decrypt(self):
        s = "SIXTEEN  CANDLES"
        key = "YELLOW SUBMARINE"
        hex_str = bytes_to_hex(s)
        enc_str = encrypt_aes_ecb(hex_str, key)
        self.assertEqual(decrypt_aes_ecb(enc_str, key), hex_str)


class TestCBC(TestCase):
    def test_encrypt_decrypt(self):
        input_file = "matasano/tests/input_files/2.10.txt"
        hex_str = b64_file_to_hex_str(input_file)
        key = "YELLOW SUBMARINE"
        blocksize = 16
        iv = int_to_hex(0) * blocksize
        raw_file = decrypt_aes_cbc(
            hex_str, key=key, init_vector=iv, blocksize=blocksize)
        self.assertEqual(
            encrypt_aes_cbc(raw_file, key, iv, blocksize), hex_str)


class TestProfileUtils(TestCase):
    def test_encode_profile(self):
        encoded_profile = encode_profile(profile_for("foo@bar.com"))
        self.assertEqual(
            encoded_profile,
            "email=foo%40bar.com&uid=10&role=user")

    def test_decode_profile(self):
        profile = profile_for("foo@bar.com")
        encoded_profile = encode_profile(profile)
        self.assertEqual(decode_profile(encoded_profile), profile)

    def test_decode_duplicate_key(self):
        profile = profile_for("foo@bar.com")
        encoded_profile = encode_profile(profile) + "&role=admin"
        self.assertRaises(ValueError, decode_profile, encoded_profile)
