# Payment gateway
import pprint
import socket
import time

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

import crypto_utils
from crypto_utils import printStep
from crypto_utils import sendData
from crypto_utils import recvData

# Generate RSA key
pubKPG, pvKPG = crypto_utils.generate_rsa()

# Write RSA key to file
crypto_utils.save_rsa_file(pubKPG, "pubKPG.pem")

serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
host = '127.0.0.1'
port = 5556
serverSock.bind((host, port))

print('---Payment Gateway (server) ---')
serverSock.listen(1)
print('Listening for connections...')

# Merchant
merchantSock, addr1 = serverSock.accept()
print('Connected by Merchant:', addr1)

# Get pubKM
pubKM = RSA.import_key(open("pubKM.pem").read())

while True:
    print('Generated (PubKPG):', pubKPG.export_key('DER'))
    print('Generated (PvKPG):', pvKPG.exportKey('DER'))

    # ---------- STEP 4 ------------
    printStep(4)

    # Get encrypted PM and SigM(Sid,PubKC,Amount) from Merchant
    step4_dict = recvData(merchantSock)

    # Decrypt PM and SigM
    print('Decrypting (PM) and (SigM)...')
    k_enc = step4_dict.get('k')
    PM_enc = step4_dict.get('PM')
    sigm_enc = step4_dict.get('sigm')

    PM = eval(crypto_utils.hybridDecrypt(k_enc, pvKPG, PM_enc))
    sigm = eval(crypto_utils.hybridDecrypt(k_enc, pvKPG, sigm_enc))

    print('PM:')
    pprint.pprint(PM)

    # Decrypt PI and SigC(PI)
    k_enc2 = PM.get('k')
    PI_enc = PM.get('pi')
    sigc_pi_enc = PM.get('sigc_pi')

    print('Decrypting (PI) and (SigC(PI))...')

    PI = eval(crypto_utils.hybridDecrypt(k_enc2, pvKPG, PI_enc))
    sigc_pi = eval(crypto_utils.hybridDecrypt(k_enc2, pvKPG, sigc_pi_enc))

    print('PI:')
    pprint.pprint(PI)
    print('SigC(PI):', sigc_pi)

    # Verify signature (SigM(Sid,PubKC,Amount))
    sigm_items = {'sid': PI.get('sid'), 'pubKC': PI.get('pubKC'), 'amount': PI.get('amount')}
    crypto_utils.verifySignature(pubKM, str(sigm_items).encode(), sigm, 'SigM(Sid,PubKC,Amount)')

    # Verify signature (SigC(PI))
    pubKC = RSA.import_key(PI.get('pubKC'))
    signature_valid = crypto_utils.verifySignature(pubKC, str(PI).encode(), sigc_pi, 'SigC(PI)')

    # Check if card number is known
    bank = open('bank.txt', 'r').read()
    bank_dict = eval(bank)
    card_index = None
    for i, val in enumerate(bank_dict):
        if val['card_n'] == PI.get('card_n'):
            card_index = i
            break

    card_n_valid = True
    expiration_valid = True
    c_code_valid = True
    enough_money = True

    if card_index is None:
        card_n_valid = False
    else:

        # Check challenge code
        if not PI.get('c_code') == bank_dict[card_index]['c_code']:
            c_code_valid = False

        # Check card expiration date
        if not PI.get('card_exp') == bank_dict[card_index]['card_exp']:
            expiration_valid = False

        # Check balance
        if expiration_valid and c_code_valid and signature_valid:
            amount = float(PI.get('amount'))
            if bank_dict[card_index]['balance'] >= amount:
                bank_dict[card_index]['balance'] -= amount
                for i, val in enumerate(bank_dict):
                    if val['card_n'] == 'merchant':
                        bank_dict[i]['balance'] += amount
                        break
                open("bank.txt", "w").write(str(bank_dict))
            else:
                enough_money = False

    # ---------- STEP 5 ------------
    printStep(5)

    # Create the PG's response
    resp = ''
    if not card_n_valid:
        resp += 'Card number is not known by PG. '
    if not c_code_valid:
        resp += 'Challenge code is incorrect. '
    if not expiration_valid:
        resp += 'Expiration date is incorrect. '
    if not enough_money:
        resp += 'Not enough money in account. '
    if not signature_valid:
        resp += 'Signature is not valid. '
    if resp == '':
        resp = 'Payment successful.'
    print('Response = ', resp)

    # Make SigPG(Resp,Sid,Amount,NC)
    sigpg_aux = {'resp': resp, 'sid': PI.get('sid'), 'amount': PI.get('amount'), 'nc': PI.get('nc')}
    sigpg = crypto_utils.makeSignature(pvKPG, str(sigpg_aux).encode())
    print('SigPG(Resp,Sid,Amount,NC) =', sigpg)

    # Generate session key
    k = get_random_bytes(16)
    print('Generated (session key) = ', k)

    # Encrypting
    print('Encrypting...')
    k_enc3, resp_enc = crypto_utils.hybridEncrypt(k, pubKM, resp.encode())
    k_enc4, sid_enc = crypto_utils.hybridEncrypt(k, pubKM, PI.get('sid'))
    k_enc5, sigpg_enc = crypto_utils.hybridEncrypt(k, pubKM, sigpg)

    step5_dict = {'resp': resp_enc, 'sid': sid_enc, 'sigpg': sigpg_enc, 'k': k_enc3}

    # Send data to Merchant
    sendData(merchantSock, step5_dict)

    break
