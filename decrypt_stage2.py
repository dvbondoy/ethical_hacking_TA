from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import subprocess


def decrypt_with_aes(file_path, flag):
    # Hash the flag using SHA-256
    key = hashlib.sha256(flag.encode()).digest()

    # Read the encrypted data
    with open(file_path, 'rb') as f:
        ciphertext = f.read()

    # AES decryption - assuming ECB mode (adjust if needed)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode()

# Example usage:
# decrypted_flag2 = decrypt_stage2('stage2.enc', '~⌂q*/:|qs~;qs|')
# print("Stage 2 Flag:", decrypted_flag2)


def decrypt_with_openssl(enc_file, password, cipher='aes-256-cbc'):
    output_file = 'decrypted_stage2.bin'
    key = hashlib.sha256(password.encode()).hexdigest()[:32]  # Ensure key is 32 bytes for AES-256
    cmd = [
        'openssl', 'enc', '-d',
        f'-{cipher}',
        '-in', enc_file,
        '-out', output_file,
        '-k', key,
        '-md', 'md5'  # Matches OpenSSL’s key derivation in app3.py
    ]
    result = subprocess.run(cmd, capture_output=True)
    
    if result.returncode == 0:
        print(f"Decryption succeeded using {cipher}. Decrypted content in {output_file}")
    else:
        print(f"Decryption failed using {cipher}")
        print("Error:", result.stderr.decode())

# Try it out
# decrypt_with_openssl('stage2.enc', '~⌂q*/:|qs~;qs|')

if __name__ == "__main__":
    # Example flag for testing
    flag = "flag{~q*/:|qs~;qs|}"
    decrypted_flag2 = decrypt_with_openssl('stage2.enc', flag)
    # decrypted_flag2 = decrypt_stage2('stage2.enc', flag)
    print("Stage 2 Flag:", decrypted_flag2)