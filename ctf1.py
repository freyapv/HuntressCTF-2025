import base64

# (these are the values from the script you provided)
cipher_b64 = "zGdgT6GHR9uXJ682kdam1A5TbvJP/Ap87V6JxICzC9ygfX2SUoIL/W5cEP/xekJTjG+ZGgHeVC3clgz9x5X5mgWLGNkga+iixByTBkka0xbqYs1TfOVzk2buDCjAesdisU887p9URkOL0rDve6qe7gjyab4H25dPjO+dVYkNuG8wWQ=="
key_b64    = "me6Fzk0HR9uXTzzuFVLORM2V+ZqMbA=="

ct = base64.b64decode(cipher_b64)
key = base64.b64decode(key_b64)
pt = bytes(ct[i] ^ key[i % len(key)] for i in range(len(ct)))

# The decoded payload contains 10 pushes of 4 bytes each; emulate the shellcode's decoding:
# extract the 40 bytes that are pushed (these are at the start of pt because pushes are encoded there),
# reverse the 4-byte words, XOR with 0xA5 and print ascii.
# (In the analysis I parsed the objdump and reconstructed exactly; this is the same logic.)
push_words = [
    b'\x93\xd8\x84\x84', b'\x90\xc3\xc6\x97', b'\xc3\x90\x93\x92', b'\x90\xc4\xc3\xc7',
    b'\x9c\x93\x9c\x93', b'\xc0\x9c\xc6\xc6', b'\x97\xc6\x9c\x93', b'\x94\xc7\x9d\xc1',
    b'\xde\xc1\x96\x91', b'\xc3\xc9\xc4\xc2'
]
buf = b''.join(reversed(push_words))
decoded = bytes([b ^ 0xa5 for b in buf])
print(decoded[:0x26].decode())  # prints the flag
