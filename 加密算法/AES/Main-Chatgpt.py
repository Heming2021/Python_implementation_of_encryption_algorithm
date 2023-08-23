from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

def derive_key(key, length):
    return hashlib.sha256(key.encode('utf-8')).digest()[:length]

def encrypt(key, text):
    key = derive_key(key, 32)  # 使用SHA-256派生一个32字节长的密钥

    text = text.encode('utf-8')
    iv = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(text, AES.block_size))

    encrypted_text = base64.b64encode(iv + ciphertext).decode('utf-8')
    return encrypted_text

def decrypt(key, encrypted_text):
    key = derive_key(key, 32)
    encrypted_text = base64.b64decode(encrypted_text)

    if len(encrypted_text) < 16:
        raise ValueError("Invalid encrypted text.")

    iv = encrypted_text[:16]
    ciphertext = encrypted_text[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
    return decrypted_text

# 示例
key = "my_secret_key"
message = "Hello, World!"

encrypted_message = encrypt(key, message)
print("Encrypted:", encrypted_message)

decrypted_message = decrypt(key, encrypted_message)
print("Decrypted:", decrypted_message)