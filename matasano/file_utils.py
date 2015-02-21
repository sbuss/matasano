from hex_utils import b64_to_hex


def b64_file_to_hex_str(infile):
    with open(infile, 'r') as f:
        contents = f.read().replace("\n", "")
    return b64_to_hex(contents)
