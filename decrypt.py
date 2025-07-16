from hashlib import sha256
from Crypto.Cipher import AES

def confuse(input_str):
    return ''.join(chr(ord(c) ^ 13) for c in input_str[::-1])

# First flag
data = "q~|6s~|q7\"'|rs"
flag1 = "Terminal7q|~s6|~q"
print("First flag:", flag1)
key_str = sha256(flag1.encode()).hexdigest()[:32]
key = key_str.encode('utf-8')

# Load encrypted file
with open("stage2.enc", "rb") as f:
    data = f.read()

nonce = data[:16]
tag = data[16:32]
ciphertext = data[32:]

# Decrypt
try:
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    # Save and/or print result
    print("Decrypted content:", plaintext.decode(errors="ignore"))
except Exception as e:
    print("Decryption failed:", str(e))