from unittest import TestCase

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
