import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

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

def encrypt_file(file_path, public_key):
    print(f"Encrypting file: {file_path}")
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as f:
        f.write(ciphertext)

def decrypt_file(encrypted_file_path, private_key):
    print(f"Decrypting file: {encrypted_file_path}")
    with open(encrypted_file_path, 'rb') as f:
        ciphertext = f.read()

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    decrypted_file_path = encrypted_file_path[:-4]  # remove '.enc'
    with open(decrypted_file_path, 'wb') as f:
        f.write(plaintext)

# Example usage
private_key, public_key = generate_key_pair()

# Save keys to files
save_key_to_file(private_key, 'private_key.pem')
save_key_to_file(public_key, 'public_key.pem', is_private=False)

# Specify the folder to partially encrypt
folder_path = r'C:\Users\Qais AL-yamani\Documents\TPM_project2\sensitive_data'

# List all files in the folder
files_to_encrypt = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]

# Encrypt selected files
for file_to_encrypt in files_to_encrypt:
    file_path = os.path.join(folder_path, file_to_encrypt)
    encrypt_file(file_path, public_key)

# Decrypt a specific file (example)
encrypted_file_path = os.path.join(folder_path, files_to_encrypt[0] + '.enc')
decrypt_file(encrypted_file_path, private_key)
