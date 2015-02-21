from unittest import TestCase

from ..decrypt import aes_ecb as decrypt_aes_ecb
from ..decrypt import aes_ecb_cbc
from ..encrypt import aes_ecb as encrypt_aes_ecb
from ..encrypt import aes_ecb_cbc as encrypt_aes_ecb_cbc
from ..file_utils import b64_file_to_hex_str
from ..hex_utils import bytes_to_hex
from ..hex_utils import int_to_hex
from ..hex_utils import pkcs7_padding


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
        raw_file = aes_ecb_cbc(
            hex_str, key=key, init_vector=iv, blocksize=blocksize)
        self.assertIn("Play that funky music white boy", raw_file)


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
        raw_file = aes_ecb_cbc(
            hex_str, key=key, init_vector=iv, blocksize=blocksize)
        self.assertEqual(
            encrypt_aes_ecb_cbc(raw_file, key, iv, blocksize), hex_str)
