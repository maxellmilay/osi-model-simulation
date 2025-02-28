def xor_encrypt_decrypt(data, key=0x42):
    return bytes([b ^ key for b in data])
