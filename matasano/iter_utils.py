from functools import partial
from itertools import imap
from itertools import izip


def group(iterable, num_items):
    """Return elements from an iterable, num_items at a time."""
    return imap(None, *([iter(iterable)] * num_items))


def yield_blocks(hex_str, block_len_bytes):
    """Yield blocks, as bytes, of hex_str that are block_len_bytes long.

    From http://code.activestate.com/recipes/439095-iterator-to-return-items-n-at-a-time/  # nopep8
    """
    return (''.join(x) for x in group(hex_str, block_len_bytes * 2))


def transpose_blocks(blocks):
    """Transpose an iterable of hex strings.

    That is, given an iterable of equal length strings, ['dead', 'beef']
    return ['debe', adef']
    """
    grp = partial(group, num_items=2)
    j = ''.join
    return imap(j, (imap(j, x) for x in izip(*imap(grp, blocks))))
    """
    The above is equivalent to this more verbose nested loop:

    transposed_blocks = []
    for block in blocks:
        for pos in range(len(block) / 2):
            byte = block[pos*2:pos*2+2]
            if pos > len(transposed_blocks) - 1:
                transposed_blocks.append(byte)
            else:
                transposed_blocks[pos] += byte
    return transposed_blocks
    """
