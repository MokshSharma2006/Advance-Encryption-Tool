# Import necessary cryptographic and system modules
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  as crypt# Key derivation function
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as AG    # AES GCM mode (authenticated encryption)
from cryptography.hazmat.primitives import hashes                 # Cryptographic hash functions
from cryptography.hazmat.backends import default_backend as back      # Backend for cryptographic primitives
import os                                                         # For file and random byte handling

# Derives a secure 256-bit AES key from the user-provided password and a random salt
def keys(password: str, salt: bytes) -> bytes:
    kdf = crypt(
        algorithm=hashes.SHA256(),      # Use SHA-256 as the hashing algorithm
        length=32,                      # Key length: 32 bytes (256 bits for AES-256)
        salt=salt,                      # Random salt to defend against rainbow table attacks
        iterations=100000,              # Number of iterations to make brute-force slower
        backend=back()       # Use default cryptographic backend
    )
    return kdf.derive(password.encode())  # Derive and return the key from the password

# Encrypts the specified file using AES-256-GCMs
def encrypt(file_path, password):
    salt = os.urandom(16)                # Generate a secure 16-byte salt
    key = keys(password, salt)     # Derive a key using the password and salt
    aes = AG(key)                 # Initialize AES in GCM mode (secure + integrity-checked)
    nonce = os.urandom(12)               # Generate a 12-byte nonce (GCM standard)

    with open(file_path, 'rb') as f:
        data = f.read()                  # Read the contents of the file

    encrypted = aes.encrypt(nonce, data, None)  # Encrypt the data (no associated data)

    # Save encrypted file with format: [salt][nonce][cipher]
    with open(file_path + ".enc", 'wb') as f:
        f.write(salt + nonce + encrypted)

    print(f"File encrypted: {file_path}.enc")

# Decrypts a previously encrypted file (with .enc extension) using the correct password
def decrypt(file_path, password):
    with open(file_path, 'rb') as f:
        content = f.read()               # Read entire encrypted content

    salt = content[:16]                 # Extract salt (first 16 bytes)
    nonce = content[16:28]              # Extract nonce (next 12 bytes)
    cipher = content[28:]           # The rest is the encrypted data

    key = keys(password, salt)    # Derive the decryption key
    aes = AG(key)                # Initialize AES-GCM with derived key

    try:
        decrypted = aes.decrypt(nonce, cipher, None)  # Try decrypting
        output = file_path.replace(".enc", ".dec")       # Name for decrypted file

        with open(output, 'wb') as f:
            f.write(decrypted)          # Write the decrypted data

        print(f"✅ File decrypted: {output}")
    except Exception as e:
        # If password is wrong or file is corrupted, raise an error
        print("Decryption failed.")
