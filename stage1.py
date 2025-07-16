import hashlib
import os
from Crypto.Cipher import AES

# stage1.py
def confuse(input_str):
    return ''.join(chr(ord(c) ^ 13) for c in input_str[::-1])

def deconfuse(obfuscated):
    # XOR each character with 13
    xor_decoded = ''.join(chr(ord(c) ^ 13) for c in obfuscated)
    # Then reverse the string
    return xor_decoded[::-1]

def encrypt_file(input_file, output_file, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_EAX)
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    with open(output_file, 'wb') as f:
        f.write(cipher.nonce + tag + ciphertext)

def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        nonce, tag, ciphertext = f.read(32), f.read(32), f.read()
    cipher = AES.new(key.encode('utf-8'), AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    with open(output_file, 'wb') as f:
        f.write(plaintext)

def main():
    # This is an obfuscated version of flag1
    data = "q~|6s~|q7\"'|rs"
    first_flag = deconfuse(data)

    print("Welcome to Stage 1.")
    print("Find the correct function and decode the string.")
    print("First flag: "+first_flag)

    print("Now, you can proceed to Stage 2.")
    # hash the first_flag"
    hashed_string = hashlib.sha256(first_flag.encode('utf-8')).hexdigest()
    print("Hashed first flag (SHA256):", hashed_string)

    # encrypt test.txt with the hashed string
    # try:
    #     encrypt_file("test.txt", "test.enc", hashed_string[:32])
    #     print("Encrypted Stage 2 file successfully.")
    # except Exception as e:
    #     print("Error during encryption:", str(e))

    # decrypt test.txt with the hashed string
    try:
        decrypt_file("stage2.enc", "stage2.dec.txt", hashed_string[:32])
        print("Decrypted Stage 2 file successfully.")
    except Exception as e:
        print("Error during decryption:", str(e))

    
if __name__ == "__main__":
    main()

# 10096f459035e95d0b8c058e08db4e23b2e30570c7b490459f39d312433cf3a5 terminal
# 855e66c95029167b4432b038102ec16c7dd337201be419e9035e31315db104cb