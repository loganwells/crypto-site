import rsa
import hashlib
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import os

def encrypt_file_aes(file_data, key_size=128, mode='CBC'):
    key = get_random_bytes(key_size // 8)
    iv = get_random_bytes(16)

    if mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv)
    elif mode == 'CFB':
        cipher = AES.new(key, AES.MODE_CFB, iv)
    else:
        raise ValueError("Unsupported AES mode")

    ciphertext = cipher.encrypt(pad(file_data, AES.block_size))
    return iv + key + ciphertext  # send all as one for now


from Crypto.Util.Padding import unpad

def decrypt_file_aes(encrypted_data, mode='CBC'):
    iv = encrypted_data[:16]
    key = encrypted_data[16:32]  # 128-bit (16 bytes) key
    ciphertext = encrypted_data[32:]

    if mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv)
    elif mode == 'CFB':
        cipher = AES.new(key, AES.MODE_CFB, iv)
    else:
        raise ValueError("Unsupported AES mode")

    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted

def encrypt_file_3des(file_data):
    key = DES3.adjust_key_parity(get_random_bytes(24))
    iv = get_random_bytes(8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(file_data, DES3.block_size))
    return iv + key + encrypted  # prepend iv and key

def decrypt_file_3des(encrypted_data):
    iv = encrypted_data[:8]
    key = encrypted_data[8:32]
    ciphertext = encrypted_data[32:]
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    return decrypted

def generate_rsa_keys():
    (pub_key, priv_key) = rsa.newkeys(2048)
    pub_pem = pub_key.save_pkcs1()
    priv_pem = priv_key.save_pkcs1()
    return pub_pem, priv_pem

def encrypt_file_rsa(file_data, pub_key_pem):
    pub_key = rsa.PublicKey.load_pkcs1(pub_key_pem)
    return rsa.encrypt(file_data, pub_key)

def decrypt_file_rsa(encrypted_data, priv_key_pem):
    priv_key = rsa.PrivateKey.load_pkcs1(priv_key_pem)
    return rsa.decrypt(encrypted_data, priv_key)

def hash_file_sha(file_data, algo='sha256'):
    if algo == 'sha256':
        hash_obj = hashlib.sha256()
    elif algo == 'sha3_256':
        hash_obj = hashlib.sha3_256()
    else:
        raise ValueError("Unsupported hash algorithm")
    
    hash_obj.update(file_data)
    return hash_obj.hexdigest()
