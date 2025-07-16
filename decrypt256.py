from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_file(input_file, output_file, key, iv):
    with open(input_file, 'rb') as f:
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    with open(output_file, 'wb') as f:
        f.write(plaintext)

# Example usage:
# key and iv must be bytes objects of length 32 and 16 respectively
# key = b'your-32-byte-key................'
# iv = b'your-16-byte-iv..'
# decrypt_file('encrypted.bin', 'decrypted.txt', key, iv)