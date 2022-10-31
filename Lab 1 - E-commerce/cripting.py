from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Signature.pkcs1_15 import PKCS115_SigScheme
from Cryptodome.Util.Padding import unpad, pad

BLOCK_SIZE = 16

def keyGen():
    keysG = []

    privateKey = RSA.generate(1028)

    keysG.append(privateKey.public_key())
    keysG.append(privateKey)

    return keysG


def publicEncryption(message, publicKey):
    try:
        encryptor = PKCS1_OAEP.new(publicKey)
        encrypted = encryptor.encrypt(message)

        return encrypted
    except Exception as e:
        print(e.__class__)


def privateDecryption(message, privateKey):
    decryptor = PKCS1_OAEP.new(privateKey)
    decrypted = decryptor.decrypt(message)

    return decrypted

def privateSigning(message, privateKey):
    hash = SHA256.new(message)
    signer = PKCS115_SigScheme(privateKey)
    signature = signer.sign(hash)

    return signature


def publicSignVf(message, publicKey, semnatura):
    hash = SHA256.new(message)
    signer = PKCS115_SigScheme(publicKey)
    try:
        signer.verify(hash, semnatura)
        return 1
    except:
        return 0


def encryptAES(msg, secretKey, nonce):
    cipherAES = AES.new(secretKey, AES.MODE_GCM, nonce)
    ciphertext = cipherAES.encrypt(msg)

    return ciphertext

def decryptAES(encryptedMsg, secretKey, nonce):
    cipherAES = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = cipherAES.decrypt(encryptedMsg)

    return plaintext


def hybridEncryption(text, key):
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(key)
    encrypted_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_ECB)
    encrypted_text = cipher_aes.encrypt(pad(text, BLOCK_SIZE))

    info = {
        "enc_key": encrypted_session_key,
        "enc_text": encrypted_text
    }
    return info


def hybridDecription(info, decrypt_key):
    cipher_rsa = PKCS1_OAEP.new(decrypt_key)
    decrypted_session_key = cipher_rsa.decrypt(info["enc_key"])

    cipher_rsa = AES.new(decrypted_session_key, AES.MODE_ECB)
    decrypted_text = unpad(cipher_rsa.decrypt(info["enc_text"]), BLOCK_SIZE)

    info = {
        "dec_key": decrypted_session_key,
        "dec_text": decrypted_text
    }
    return info