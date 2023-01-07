#!/bin/env python3

import base64
import hashlib

from Crypto.Cipher import AES

def bytes_hex(bytes):
	return ''.join(format(x, '02x') for x in bytes)

# "aDOBofVYUNVnmp7"

bs = AES.block_size
key = hashlib.sha256("aDOBofVYUNVnmp7".encode()).digest()
# plaintext = "I was lost, but now I'm found..."
iv = key[:bs]

# key = 0x9214CA35BC11B93BD05F09A95D287DEB858BF6CA8F72E8194B7D41A58E2244C8.to_bytes(32, 'big')
# iv = 0x1AA74B5E181C746AC48EA4ADA282471E.to_bytes(16, 'big')


print(bytes_hex(key))
# 4c66bf1aca3dc2cdca1f4ee2d177b7168862ecf6247d4f0cb19ac5a98075c925
# Find first cipher block from second
# enc = 0x6ce17e8f1a200b42b97dd3f6fb1a0ec4.to_bytes(16, 'big')

ecb_cipher = AES.new(key, AES.MODE_CBC, iv)
enc = ecb_cipher.encrypt(b"test")
# dec = ecb_cipher.decrypt(enc)

print(bytes_hex(enc))
# print(dec)
