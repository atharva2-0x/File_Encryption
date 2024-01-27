from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os

class FileEncryptionUtility:
    def __init__(self, key):
        self.key = key

    def encrypt_file(self, input_path, output_path):
        with open(input_path, 'rb') as file:
            plaintext = file.read()

        
        iv = os.urandom(16)  
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        with open(output_path, 'wb') as file:
            file.write(iv + ciphertext)

    def decrypt_file(self, input_path, output_path):
        with open(input_path, 'rb') as file:
            ciphertext = file.read()
            iv = ciphertext[:16]  
            ciphertext = ciphertext[16:]
        # iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
 
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        # decrypted_data = decryptor.finalize()

        
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        original_data = unpadder.update(decrypted_data) + unpadder.finalize()

        with open(output_path, 'wb') as file:
            file.write(original_data)

def generate_key():
   
    return os.urandom(32)

def main():
    key = generate_key()
    file_utility = FileEncryptionUtility(key)

    input_file = 'example.txt'
    encrypted_file = 'example_encrypted.txt'
    decrypted_file = 'example_decrypted.txt'

    
    file_utility.encrypt_file(input_file, encrypted_file)
    print(f'File "{input_file}" encrypted and saved as "{encrypted_file}".')

    
    file_utility.decrypt_file(encrypted_file, decrypted_file)
    print(f'File "{encrypted_file}" decrypted and saved as "{decrypted_file}".')

if __name__ == "__main__":
    main()