from unittest import skip as skip_test
from unittest import TestCase

from ..decrypt import _get_keysize_candidates
from ..decrypt import _transpose_blocks
from ..decrypt import _yield_blocks
from ..decrypt import decrypt_repeated_key_xor
from ..decrypt import single_byte_xor
from ..decrypt import find_encrypted_hex_string
from ..encrypt import xor_encrypt_string
from ..hex_utils import b64_to_hex
from ..hex_utils import bytes_to_hex
from ..hex_utils import hamming_distance
from ..hex_utils import hex_to_b64
from ..hex_utils import hexxor
from ..hex_utils import int_to_hex


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
        infile = "matasano/tests/input_files/1.4.txt"
        out = find_encrypted_hex_string(infile)
        self.assertEqual(out.string, "Now that the party is jumping\n")

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

    @skip_test("SLOOOOOOW")
    def test_challenge6_decrypt_repeating_key_xor(self):
        """
        * File b64 encoded
        * key size anywhere from 2 to 40
        """
        infile = "matasano/tests/input_files/1.6.txt"
        hex_str = ""
        with open(infile, 'r') as f:
            for line in f:
                hex_str += b64_to_hex(line.strip())
        keys = decrypt_repeated_key_xor(hex_str)
        self.assertIn('Vanilla Ice', keys[0][4])


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


class TestDecryptUtils(TestCase):
    def test_keysize_candidates(self):
        string = ("And it's so sad to see the world agree\n"
                  "That they'd rather see their faces fill with flies\n"
                  "All when I'd want to keep white roses in their eyes")
        key = "aeroplane"
        enc_str = xor_encrypt_string(string, key)
        keysizes = _get_keysize_candidates(enc_str, (1, 50))
        # Only 35 candidates because we don't have a long enough string to
        # get good stats on keys longer than 35 bytes
        self.assertEqual(len(keysizes), 35)
        # Not the first candidate, but up there!
        self.assertEqual(keysizes[2].keysize, len(key))

    def test_keysize_candidates_repeated_letters(self):
        string = ("the wonderful thing about tiggers\n"
                  "is tiggers are wonderful things\n"
                  "their tops are made out of rubber\n"
                  "their bottoms are made out of springs")
        key = "winnie"
        enc_str = xor_encrypt_string(string, key)
        keysizes = _get_keysize_candidates(enc_str, (1, 50))
        self.assertEqual(keysizes[0].keysize, len(key))

    def test_yield_blocks(self):
        s = "who's in a bunker? who's in a bunker?"
        hex_str = bytes_to_hex(s)
        block_size = 1
        block_generator = _yield_blocks(hex_str, block_size)
        self.assertEqual(
            len(list(block_generator)), len(s))
        block_generator = _yield_blocks(hex_str, block_size)
        self.assertEqual(len(block_generator.next()), block_size * 2)
        self.assertEqual(block_generator.next(), bytes_to_hex('h'))

    def test_transpose_blocks(self):
        s = ['dead', 'beef', 'abcd']
        self. assertEqual(list(_transpose_blocks(s)), ['debeab', 'adefcd'])
