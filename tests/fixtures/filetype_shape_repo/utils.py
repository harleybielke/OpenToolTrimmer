_NUM_SIGNATURE_BYTES = 8192


def get_signature_bytes(path):
    with open(path, 'rb') as fp:
        return bytearray(fp.read(_NUM_SIGNATURE_BYTES))
