from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Generate RSA keys for User A
private_key = rsa.generate_private_key(65537, 2048)
public_key = private_key.public_key()

with open("private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()))
with open("public_key.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))

message = "Secret message from User B"
message_bytes = message.encode()

# Generate AES key and IV
aes_key = os.urandom(32)
iv = os.urandom(16)

# Encrypt message with AES
cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
enc = cipher.encryptor()
enc_message = enc.update(message_bytes) + enc.finalize()

# Encrypt AES key with User A's public RSA key
enc_aes_key = public_key.encrypt(
    aes_key,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

with open("encrypted_message.bin", "wb") as f: f.write(enc_message)
with open("aes_key_encrypted.bin", "wb") as f: f.write(enc_aes_key)
with open("iv.bin", "wb") as f: f.write(iv)

# User A: Load private key
with open("private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

with open("encrypted_message.bin", "rb") as f: enc_message = f.read()
with open("aes_key_encrypted.bin", "rb") as f: enc_aes_key = f.read()
with open("iv.bin", "rb") as f: iv = f.read()

dec_aes_key = private_key.decrypt(
    enc_aes_key,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

dec_cipher = Cipher(algorithms.AES(dec_aes_key), modes.CFB(iv))
dec = dec_cipher.decryptor()
decrypted_message = dec.update(enc_message) + dec.finalize()

with open("decrypted_message.txt", "wb") as f:
    f.write(decrypted_message)

print("Decrypted message:", decrypted_message.decode())