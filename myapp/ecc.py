# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from cryptography.fernet import Fernet
# import os
# import base64
# # Generate ECC private key for server
# server_private_key = ec.generate_private_key(ec.SECP384R1())

# # Generate ECC public key for server
# server_public_key = server_private_key.public_key()

# # Serialize public key to be shared with client
# server_public_key_bytes = server_public_key.public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo
# )

# # Client side - Load server's public key
# server_public_key = serialization.load_pem_public_key(server_public_key_bytes)

# # Generate ECC private key for client
# client_private_key = ec.generate_private_key(ec.SECP384R1())

# # Generate ECC public key for client
# client_public_key = client_private_key.public_key()

# # Serialize client public key to be shared with server
# client_public_key_bytes = client_public_key.public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo
# )

# # Server side - Load client's public key
# client_public_key = serialization.load_pem_public_key(client_public_key_bytes)

# # Generate a symmetric key using ECDH (Elliptic Curve Diffie-Hellman) for key exchange
# server_shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)
# client_shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)

# # Derive a symmetric key from the shared key
# derived_key_server = HKDF(
#     algorithm=hashes.SHA256(),
#     length=32,
#     salt=None,
#     info=b'handshake data'
# ).derive(server_shared_key)

# derived_key_client = HKDF(
#     algorithm=hashes.SHA256(),
#     length=32,
#     salt=None,
#     info=b'handshake data'
# ).derive(client_shared_key)

# # Ensure both derived keys are identical
# assert derived_key_server == derived_key_client

# # Convert the derived key into a Fernet key (Fernet keys must be 32 bytes and base64-encoded)
# fernet_key = Fernet(base64.urlsafe_b64encode(derived_key_server))




from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Generate ECC private key
private_key = ec.generate_private_key(ec.SECP256R1())

# Serialize private key to PEM format
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Serialize public key to PEM format
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Load private key from PEM
loaded_private_key = serialization.load_pem_private_key(
    private_pem,
    password=None
)

# Load public key from PEM
loaded_public_key = serialization.load_pem_public_key(public_pem)

# Encrypt data
def encrypt_message(public_key, message):
    # Get the public key in a format that can be used for key exchange
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Use ECDH for key exchange
    shared_key = loaded_private_key.exchange(ec.ECDH(), serialization.load_pem_public_key(public_key_bytes))
    
    # Derive a key using PBKDF2 or other KDF
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'salt',
        iterations=100000,
    )
    key = kdf.derive(shared_key)
    
    # Pad the message using PKCS#7
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message) + padder.finalize()
    
    # Encrypt the message using AES
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    
    return iv + encrypted_message

# Decrypt data
def decrypt_message(private_key, encrypted_message):
    # Get the public key in a format that can be used for key exchange
    public_key_bytes = loaded_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Use ECDH for key exchange
    shared_key = private_key.exchange(ec.ECDH(), serialization.load_pem_public_key(public_key_bytes))
    
    # Derive a key using PBKDF2 or other KDF
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'salt',
        iterations=100000,
    )
    key = kdf.derive(shared_key)
    
    # Decrypt the message using AES
    iv = encrypted_message[:16]
    encrypted_message = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    
    # Unpad the message using PKCS#7
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    
    return unpadded_message

# Example usage
message = b"Hello shiva "
encrypted_message = encrypt_message(loaded_public_key, message)
decrypted_message = decrypt_message(loaded_private_key, encrypted_message)
print(encrypted_message)
print(decrypted_message)