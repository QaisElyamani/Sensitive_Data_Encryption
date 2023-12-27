import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_file(file_path, public_key):
    print(f"Encrypting file: {file_path}")
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Generate a random symmetric key for data encryption (AES in this case)
    symmetric_key = os.urandom(32)  # 256-bit key for AES-256

    # Encrypt the symmetric key with the public key (RSA)
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Use the symmetric key to encrypt the actual data (AES)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as f:
        # Write the encrypted symmetric key followed by the encrypted data
        f.write(encrypted_symmetric_key + ciphertext)

    print(f"Encryption successful. Encrypted file: {encrypted_file_path}")
