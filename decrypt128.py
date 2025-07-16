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
# key and iv must be 16 bytes (128 bits)
key = b'your16bytekey__'  # Replace with your actual key
iv = b'your16byteiv___'   # Replace with your actual IV

decrypt_file('encrypted_file.bin', 'decrypted_file.txt', key, iv)