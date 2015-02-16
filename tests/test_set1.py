from unittest import TestCase

import hex_utils


class TestHexToBase64(TestCase):
    # Challenge 1
    def test_h2b64(self):
        inp = ("49276d206b696c6c696e6720796f75722"
               "0627261696e206c696b65206120706f69"
               "736f6e6f7573206d757368726f6f6d")
        out = ("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsa"
               "WtlIGEgcG9pc29ub3VzIG11c2hyb29t")
        self.assertEqual(hex_utils.hex_to_b64(inp), out)


class TestHexxor(TestCase):
    # Challenge 2
    def test_hexxor(self):
        hex1 = "1c0111001f010100061a024b53535009181c"
        hex2 = "686974207468652062756c6c277320657965"
        out = "746865206b696420646f6e277420706c6179"
        self.assertEqual(hex_utils.hexxor(hex1, hex2), out)
