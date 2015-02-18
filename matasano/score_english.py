from __future__ import division
from collections import Counter
import math
from itertools import chain

# Frequencies from
# http://ekatetra.enetpress.com/downloads/LF_HalfMillionFrequencies.pdf
english_letter_counts = {
    "e": 49614,
    "t": 39144,
    "a": 31374,
    "o": 30587,
    "i": 28741,
    "n": 28013,
    "s": 27406,
    "r": 25304,
    "h": 17685,
    " ": 81476,
    "l": 15376,
    "d": 14357,
    "c": 12881,
    "u": 11178,
    "m": 9970,
    "p": 9736,
    "f": 9038,
    "g": 7710,
    "w": 6747,
    "b": 5870,
    "v": 4594,
    "k": 3009,
    "x": 926,
    "j": 521,
    "q": 465,
    "z": 428,
}


def get_letter_frequencies(count_dict):
    """Return the letter frequencies for a given dict of letter counts.

    Args:
        count_dict: A dictionary of letter:count mappings
    Returns a dictionary of letter:frequency mappings
    """
    total_letter_count = sum(count_dict.values())
    freqs = {}
    for (letter, count) in count_dict.iteritems():
        freqs[letter] = count / total_letter_count
    return freqs


english_letter_frequencies = get_letter_frequencies(english_letter_counts)


def get_letter_counts(str_):
    """Get a dictionary of letter counts for the given string.

    Args:
        str_: Any str
    Returns a dictionary of letter:count mappings
    """
    return dict(Counter(str_))


def kullback_leibler_divergence(p, q):
    """Return the KL-Divergence of q from p, where they are both discrete.

    Args:
        p, q: Two discrete probability distributions.
    """
    null = 1e-10
    return sum(p.get(key, null) * math.log(p.get(key, null) / q.get(key, null))
               for key in set(chain(p.keys(), q.keys())))


def sentence_is_english(sentence):
    """Given a sentence, return the probability it is English.

    This is done by finding the letter frequencies in the sentence and then
    calculating the RMSE against standard english frequencies.
    """
    sentence = sentence.lower()
    letter_counts = get_letter_counts(sentence)
    letter_freqs = get_letter_frequencies(letter_counts)
    return kullback_leibler_divergence(
        english_letter_frequencies, letter_freqs)
