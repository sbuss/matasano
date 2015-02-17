from unittest import skip as skip_test
from unittest import TestCase

from decrypt import single_byte_xor
from decrypt import find_encrypted_hex_string
from encrypt import xor_encrypt_string
from hex_utils import bytes_to_hex
from hex_utils import hamming_distance
from hex_utils import hex_to_b64
from hex_utils import hexxor
from hex_utils import int_to_hex


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

    @skip_test("SLOOOOOOW")
    def test_challenge4_find_encrypted_string(self):
        infile = "tests/input_files/1.4.txt"
        out = find_encrypted_hex_string(infile)
        self.assertEqual(out[1].string, "Now that the party is jumping\n")

    def test_challenge5_ice_ice_baby(self):
        inp = ("Burning 'em, if you ain't quick and nimble\n"
               "I go crazy when I hear a cymbal")
        out = ("0b3637272a2b2e63622c2e69692a23693"
               "a2a3c6324202d623d63343c2a26226324"
               "272765272a282b2f20430a652e2c652a3"
               "124333a653e2b2027630c692b20283165"
               "286326302e27282f")
        key = "ICE"
        self.assertEqual(xor_encrypt_string(inp, key), out)

    def test_challenge6_decrypt_repeating_key_xor(self):
        """
        * File b64 encoded
        * key size anywhere from 2 to 40
        """
        pass


class TestHexUtils(TestCase):
    def test_int_to_hex(self):
        self.assertEqual(int_to_hex(1), '01')
        self.assertEqual(int_to_hex(10), '0a')
        self.assertEqual(int_to_hex(15), '0f')
        self.assertEqual(int_to_hex(16), '10')
        self.assertEqual(int_to_hex(255), 'ff')
        self.assertRaises(ValueError, int_to_hex, 256)
        self.assertRaises(ValueError, int_to_hex, -1)

    def test_hamming_distance(self):
        self.assertEqual(
            hamming_distance(
                bytes_to_hex("this is a test"),
                bytes_to_hex("wokka wokka!!!")),
            37)
