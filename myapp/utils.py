from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def decrypt_data(encrypted_data, secret_key):
    # Ensure the secret key is 32 bytes for AES-256
    secret_key = secret_key.ljust(32)[:32].encode('utf-8')

    # Extract the IV from the start of the encrypted data
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    # Create the Cipher object and decryptor
    cipher = Cipher(algorithms.AES(secret_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_data
