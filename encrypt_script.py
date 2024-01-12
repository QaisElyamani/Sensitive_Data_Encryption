import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key

def save_key_to_file(key, filename, is_private=True):
    if is_private:
        key_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        key_bytes = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    with open(filename, 'wb') as f:
        f.write(key_bytes)

def encrypt_file(file_path, public_key):
    print(f"Encrypting file: {file_path}")
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    symmetric_key = os.urandom(32)
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    aes_algorithm = algorithms.AES(symmetric_key)
    cipher = Cipher(aes_algorithm, modes.CFB(symmetric_key[:16]), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_symmetric_key + ciphertext)

    print(f"Encryption successful. Encrypted file: {encrypted_file_path}")

if __name__ == "__main__":
    private_key, public_key = generate_key_pair()

    save_key_to_file(private_key, 'private_key.pem')
    save_key_to_file(public_key, 'public_key.pem', is_private=False)

    folder_path = r'C:\Users\Qais AL-yamani\Documents\TPM_project2\sensitive_data'
    files_to_encrypt = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]

    for file_to_encrypt in files_to_encrypt:
        # Skip files that are already encrypted
        if file_to_encrypt.endswith('.enc'):
            continue

        file_path = os.path.join(folder_path, file_to_encrypt)
        encrypt_file(file_path, public_key)
