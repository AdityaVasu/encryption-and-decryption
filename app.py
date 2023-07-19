from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import secrets
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_bytes, public_key_bytes

def rsa_encrypt(public_key_bytes, message):
    public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

def rsa_decrypt(private_key_bytes, encrypted_message):
    private_key = serialization.load_pem_private_key(private_key_bytes, password=None, backend=default_backend())
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message
def aes_encrypt(key, iv, message):
    padder = sym_padding.PKCS7(128).padder()
    padded_message = padder.update(message) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return encrypted_message


def aes_decrypt(key, iv, encrypted_message):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    return decrypted_message
def generate_aes_key():
    # Generate a random AES key of 16 bytes
    return secrets.token_bytes(16)
def generate_aes_iv():
    return secrets.token_bytes(16)

def main():
    print("Welcome to the Encryption/Decryption Program!")

    private_key_bytes, public_key_bytes = generate_rsa_keys()

    while True:
        print("\nChoose an option:")
        print("1. Encrypt data using RSA")
        print("2. Decrypt data using RSA")
        print("3. Encrypt data using AES")
        print("4. Decrypt data using AES")
        print("5. Exit")

        choice = input("Enter your choice (1/2/3/4/5): ")

        if choice == "1":
            message = input("Enter the data to be encrypted: ").encode()
            encrypted_rsa = rsa_encrypt(public_key_bytes, message)
            print("Encrypted Message (RSA):", base64.b64encode(encrypted_rsa).decode())

        elif choice == "2":
            encrypted_rsa = base64.b64decode(input("Enter the encrypted RSA message: "))
            decrypted_rsa = rsa_decrypt(private_key_bytes, encrypted_rsa)
            print("Decrypted Message (RSA):", decrypted_rsa.decode())

        elif choice == "3":
            aes_key = generate_aes_key()
            print("Generated AES Key:", base64.b64encode(aes_key).decode())

            # Uncomment the following line to generate a random IV instead of asking for user input
            aes_iv = generate_aes_iv()

            aes_iv = input("Enter the AES IV (must be 16 bytes): ").encode()
            if len(aes_iv) != 16:
                print("Invalid IV length. Please provide a 16-byte IV.")
                continue

            message = input("Enter the data to be encrypted: ").encode()
            encrypted_aes = aes_encrypt(aes_key, aes_iv, message)
            print("Encrypted Message (AES):", base64.b64encode(encrypted_aes).decode())


        elif choice == "4":
            aes_key = input("Enter the AES key (must be 16 bytes): ").encode()
            aes_iv = input("Enter the AES IV (must be 16 bytes): ").encode()
            encrypted_aes = base64.b64decode(input("Enter the encrypted AES message: "))
            decrypted_aes = aes_decrypt(aes_key, aes_iv, encrypted_aes)
            print("Decrypted Message (AES):", decrypted_aes.decode())

        elif choice == "5":
            print("Exiting the program. Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
