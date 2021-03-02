# Merchant - Server
import socket
import pprint

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

import crypto_utils
from crypto_utils import printStep
from crypto_utils import sendData
from crypto_utils import recvData

# Generate RSA key
pubKM, pvKM = crypto_utils.generate_rsa()

# Write RSA key to file
crypto_utils.save_rsa_file(pubKM, "pubKM.pem")

serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

host = '127.0.0.1'
port = 5555
serverSock.bind((host, port))

print('---Merchant (server) ---')
serverSock.listen(1)
print('Listening for connections...')

# Customer
customerSock, addr1 = serverSock.accept()
print('Customer Connected:', addr1)

while True:
    # ---------- STEP 1 ------------
    printStep(1)

    print('Generated (PubKM):', pubKM.export_key('DER'))
    print('Generated (PvKM):', pvKM.exportKey('DER'))

    # Get encrypted PubKC from Customer
    step1_dict = recvData(customerSock)
    k_enc = step1_dict.get('k')
    pubKC_enc = step1_dict.get('pubKC')

    # Decrypt PubKC
    pubKC = crypto_utils.hybridDecrypt(k_enc, pvKM, pubKC_enc)
    print('Decrypted (PubKC):', pubKC)

    # ---------- STEP 2 ------------
    printStep(2)

    # Generate Sid
    sid = get_random_bytes(16)
    print('Generated (Sid) = ', sid)

    # Make RSA digital signature of Merchant on h(Sid)
    sigm_sid = crypto_utils.makeSignature(pvKM, sid)
    print('Signature of Merchant on (Sid) = ', sigm_sid)

    # Generate session key
    k = get_random_bytes(16)
    print('Generated (session key) = ', k)

    # Encrypt Sid and Sigm(Sid) and send them to Customer
    print('Encrypting...')
    k_enc, sid_enc = crypto_utils.hybridEncrypt(k, RSA.import_key(pubKC), sid)
    k_enc2, sigm_sid_enc = crypto_utils.hybridEncrypt(k, RSA.import_key(pubKC), sigm_sid)
    step2_dict = {'k': k_enc, 'sid': sid_enc, 'sigm(sid)': sigm_sid_enc}
    sendData(customerSock, step2_dict)

    # ---------- STEP 3 ------------
    printStep(3)

    # Get encrypted PM,PO from Customer
    step3_dict = recvData(customerSock)

    # Decrypt PM and PO
    k_enc = step3_dict.get('k')
    PM_enc = step3_dict.get('PM')
    PO_enc = step3_dict.get('PO')

    PM = eval(crypto_utils.hybridDecrypt(k_enc, pvKM, PM_enc))
    PO = eval(crypto_utils.hybridDecrypt(k_enc, pvKM, PO_enc))

    print('Decrypted (PM):')
    pprint.pprint(PM)

    print('Decrypted (PO):')
    pprint.pprint(PO)

    # Verify signature SigC(OrderDesc,Sid,Amount,NC)
    sigc_po_items = {'order_desc': PO.get('order_desc'), 'sid': PO.get('sid'), 'amount': PO.get('amount'),
                     'nc': PO.get('nc')}
    crypto_utils.verifySignature(RSA.import_key(pubKC), str(sigc_po_items).encode(), PO.get('sigc_po'),
                                 'SigC(OrderDesc,Sid,Amount,NC)')

    # ---------- STEP 4 ------------
    printStep(4)

    # Make SigM(Sid,PubKC,Amount)
    sid = PO.get('sid')
    amount = PO.get('amount')
    nc = PO.get('nc')

    sigm_aux = {'sid': sid, 'pubKC': pubKC, 'amount': amount}
    sigm = crypto_utils.makeSignature(pvKM, str(sigm_aux).encode())

    print('Signature of Merchant on (Sid,PubKM,Amount) = ', sigm)

    # Connect Merchant to PG
    port2 = 5556
    pgSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    pgSock.connect((host, port2))
    print('[+] Connected to Payment Gateway:', pgSock.getsockname())

    # Get pubKPG
    pubKPG = RSA.import_key(open("pubKPG.pem").read())

    # Encrypt PM and SigM
    print('Encrypting PM and SigM(Sid,PubKM,Amount) with PubKPG...')
    k2_enc, PM_enc = crypto_utils.hybridEncrypt(k, pubKPG, str(PM).encode())
    k2_enc2, sigm_enc = crypto_utils.hybridEncrypt(k, pubKPG, str(sigm).encode())

    step4_dict = {'PM': PM_enc, 'sigm': sigm_enc, 'k': k2_enc}

    # Send encrypted PM and SigM(Sid,PubKC,Amount) to Merchant
    sendData(pgSock, step4_dict)

    # ---------- STEP 5 ------------
    printStep(5)

    # Get encrypted Resp,Sid,SigPG(Resp,Sid,Amount,NC) from PG
    step5_dict = recvData(pgSock)

    # Decrypt
    k_enc4 = step5_dict.get('k')
    resp_enc = step5_dict.get('resp')
    sid_enc = step5_dict.get('sid')
    sigpg_enc = step5_dict.get('sigpg')

    # Used decode on resp because it needs to be string, not bytes
    resp = crypto_utils.hybridDecrypt(k_enc4, pvKM, resp_enc).decode()
    sid = crypto_utils.hybridDecrypt(k_enc4, pvKM, sid_enc)
    sigpg = crypto_utils.hybridDecrypt(k_enc4, pvKM, sigpg_enc)

    print('Decrypted (Resp):', resp)
    print('Decrypted (Sid):', sid)
    print('Decrypted (SigPG):', sigpg)

    # Verify SigPG(Resp,Sid,Amount,NC)
    sigpg_aux = {'resp': resp, 'sid': PO.get('sid'), 'amount': PO.get('amount'), 'nc': PO.get('nc')}
    crypto_utils.verifySignature(pubKPG, str(sigpg_aux).encode(), sigpg, 'SigPG(Resp,Sid,Amount,NC)')

    # ---------- STEP 6 ------------
    printStep(6)

    # Generate session key
    k = get_random_bytes(16)
    print('Generated (session key) = ', k)

    # Encrypting
    print('Encrypting...')
    k_enc5, resp_enc = crypto_utils.hybridEncrypt(k, RSA.import_key(pubKC), resp.encode())
    k_enc6, sid_enc = crypto_utils.hybridEncrypt(k, RSA.import_key(pubKC), sid)
    k_enc7, sigpg_enc = crypto_utils.hybridEncrypt(k, RSA.import_key(pubKC), sigpg)

    step6_dict = {'resp': resp_enc, 'sid': sid_enc, 'sigpg': sigpg_enc, 'k': k_enc5}

    # Send final data to Customer
    sendData(customerSock, step6_dict)

    break
