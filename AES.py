from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

# Function to generate a secret key for AES
def generate_key(n):
    return get_random_bytes(n // 8)  # AES key size in bytes

# Function to encrypt a plaintext string using a secret key
def encrypt(plain_text, secret_key):
    cipher = AES.new(secret_key, AES.MODE_ECB)  # AES.MODE_ECB is used to match Java's default AES mode
    encrypted_bytes = cipher.encrypt(plain_text.ljust(16))  # Pad to 16 bytes
    return b64encode(encrypted_bytes).decode('utf-8')

# Function to decrypt a ciphertext string using a secret key
def decrypt(encrypted_text, secret_key):
    cipher = AES.new(secret_key, AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(b64decode(encrypted_text))
    return decrypted_bytes.strip().decode('utf-8')

if __name__ == "__main__":
    try:
        # Generate a secret key
        secret_key = generate_key(128)
        
        # Original plaintext
        original_text = "Hello, this is a plaintext message!"
        
        # Encrypt the plaintext
        encrypted_text = encrypt(original_text, secret_key)
        print("Encrypted Text:", encrypted_text)
        
        # Decrypt the ciphertext
        decrypted_text = decrypt(encrypted_text, secret_key)
        print("Decrypted Text:", decrypted_text)
    except Exception as e:
        print("An error occurred:", e)
