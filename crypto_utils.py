import pprint

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Util.Padding import pad, unpad


def generate_rsa():
    RSA_K = RSA.generate(2048)
    pubK = RSA_K.publickey()
    pvK = RSA_K
    return pubK, pvK


def save_rsa_file(pub_key, file_name):
    file_out = open(file_name, "wb")
    file_out.write(pub_key.export_key())
    file_out.close()


def hybridEncrypt(k, pub_key, message):
    # Encrypt session key with specific public key
    cipher_rsa = PKCS1_OAEP.new(pub_key)
    k_enc = cipher_rsa.encrypt(k)

    # Encrypt message with the AES session key
    cipher_aes = AES.new(k, AES.MODE_ECB)
    encrypted_message = cipher_aes.encrypt(pad(message, 16))

    return k_enc, encrypted_message


def hybridDecrypt(k_enc, pv_key, encrypted_message):
    # Decrypt the session key with specific private key
    cipher_rsa = PKCS1_OAEP.new(pv_key)
    k = cipher_rsa.decrypt(k_enc)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(k, AES.MODE_ECB)
    decrypted_message = unpad(cipher_aes.decrypt(encrypted_message), 16)

    return decrypted_message


def makeSignature(key, message):
    h = SHA256.new(message)
    signature = pss.new(key).sign(h)

    return signature


def verifySignature(key, message, signature, name):
    h = SHA256.new(message)
    verifier = pss.new(key)
    passed = False
    try:
        verifier.verify(h, signature)
        passed = True
        print('[+] The signature', name, 'is authentic!')
    except (ValueError, TypeError):
        print('[-] The signature', name, 'is not authentic!')
    return passed

def sendData(s, data_dict):
    s.send(str(data_dict).encode())
    print('Sent encrypted: {', ", ".join([str(x) for x in data_dict.keys()]), '}')
    # pprint.pprint(data_dict)


def recvData(s):
    data = eval(s.recv(49152).decode())
    if type(data) == dict:
        print('Received encrypted: {', ", ".join([str(x) for x in data.keys()]), '}')
    else:
        print('Received encrypted: {', data, '}')

    # pprint.pprint(data)
    return data


def printStep(nr):
    print('\n---------- STEP', nr, '------------')


if __name__ == '__main__':
    generate_rsa()
