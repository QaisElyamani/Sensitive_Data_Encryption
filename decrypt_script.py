import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def load_key_from_file(filename, is_private=True):
    with open(filename, 'rb') as f:
        key_bytes = f.read()

    if is_private:
        return serialization.load_pem_private_key(
            key_bytes,
            password=None,
            backend=default_backend()
        )
    else:
        return serialization.load_pem_public_key(
            key_bytes,
            backend=default_backend()
        )

def decrypt_file(encrypted_file_path, private_key):
    print(f"Decrypting file: {encrypted_file_path}")
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()

    encrypted_symmetric_key = encrypted_data[:private_key.key_size // 8]
    ciphertext = encrypted_data[private_key.key_size // 8:]

    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(symmetric_key[:16]), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    _, filename = os.path.split(encrypted_file_path)
    decrypted_filename = 'decrypted_' + filename[:-4]

    decrypted_file_path = os.path.join(os.path.dirname(encrypted_file_path), decrypted_filename)

    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)

    print(f"Decryption successful. Decrypted file: {decrypted_file_path}")

if __name__ == "__main__":
    private_key = load_key_from_file('private_key.pem')

    folder_path = r'C:\Users\Qais AL-yamani\Documents\TPM_project2\sensitive_data'
    encrypted_files = [f for f in os.listdir(folder_path) if f.endswith('.enc')]

    for encrypted_file in encrypted_files:
        encrypted_file_path = os.path.join(folder_path, encrypted_file)
        decrypt_file(encrypted_file_path, private_key)
