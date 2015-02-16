from unittest import TestCase

from hex_utils import hex_to_b64
from hex_utils import hexxor
from hex_utils import int_to_hex
from decrypt import single_byte_xor
from decrypt import find_encrypted_hex_string


class TestSet1(TestCase):
    def test_challenge1_h2b64(self):
        inp = ("49276d206b696c6c696e6720796f75722"
               "0627261696e206c696b65206120706f69"
               "736f6e6f7573206d757368726f6f6d")
        out = ("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsa"
               "WtlIGEgcG9pc29ub3VzIG11c2hyb29t")
        self.assertEqual(hex_to_b64(inp), out)

    def test_challenge2_hexxor(self):
        hex1 = "1c0111001f010100061a024b53535009181c"
        hex2 = "686974207468652062756c6c277320657965"
        out = "746865206b696420646f6e277420706c6179"
        self.assertEqual(hexxor(hex1, hex2), out)

    def test_challenge3_decrypt_single_xor(self):
        inp = ("1b37373331363f78151b7f2b783431333"
               "d78397828372d363c78373e783a393b3736")
        out = single_byte_xor(inp, 1)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].english_score > 0)
        self.assertEqual(out[0].string, "Cooking MC's like a pound of bacon")
        out = single_byte_xor(inp, 2)
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0].string, "Cooking MC's like a pound of bacon")

    def test_challenge4_find_encrypted_string(self):
        infile = "tests/input_files/1.4.txt"
        out = find_encrypted_hex_string(infile)
        self.assertEqual(out[1].string, "Now that the party is jumping\n")


class TestHexUtils(TestCase):
    def test_int_to_hex(self):
        self.assertEqual(int_to_hex(1), '01')
        self.assertEqual(int_to_hex(10), '0a')
        self.assertEqual(int_to_hex(15), '0f')
        self.assertEqual(int_to_hex(16), '10')
        self.assertEqual(int_to_hex(255), 'ff')
        self.assertRaises(ValueError, int_to_hex, 256)
        self.assertRaises(ValueError, int_to_hex, -1)
