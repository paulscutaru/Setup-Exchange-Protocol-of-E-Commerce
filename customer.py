# Customer - client
import pprint
import socket

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import crypto_utils
from crypto_utils import printStep
from crypto_utils import sendData
from crypto_utils import recvData


merchantSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
merchantSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
host = '127.0.0.1'
port = 5555

print('--- Customer ---')
merchantSock.connect((host, port))
print('Connected to Server (Merchant):', merchantSock.getsockname())


while True:
    # ---------- STEP 1 ------------
    printStep(1)

    # Generate RSA key
    pubKC, pvKC = crypto_utils.generate_rsa()
    print('Generated (PubKC):', pubKC.export_key('DER'))
    print('Generated (PvKC):', pvKC.exportKey('DER'))

    # Get pubKM from file
    pubKM = RSA.import_key(open("pubKM.pem").read())
    pubKPG = RSA.import_key(open("pubKPG.pem").read())

    # Generate session AES key
    k = get_random_bytes(16)
    print('Generated (session key):', k)

    # Send encrypted session key and encrypted pubKC to Merchant
    print('Encrypting...')
    k_enc, pubKC_enc = crypto_utils.hybridEncrypt(k, pubKM, pubKC.export_key('DER'))
    step1_dict = {'k': k_enc, 'pubKC': pubKC_enc}
    sendData(merchantSock, step1_dict)

    # ---------- STEP 2 ------------
    printStep(2)

    # Get data from Merchant
    step2_dict = recvData(merchantSock)

    # Decrypt the received data (Sid and Sig(Sid))
    k_enc = step2_dict.get('k')
    sid = crypto_utils.hybridDecrypt(k_enc, pvKC, step2_dict.get('sid'))
    sigm_sid = crypto_utils.hybridDecrypt(k_enc, pvKC, step2_dict.get('sigm(sid)'))

    print('Decrypted (Sid):', sid)
    print('Decrypted (Sigm(Sid)):', sigm_sid)

    # Verify the signature (SigM(Sid))
    crypto_utils.verifySignature(pubKM, sid, sigm_sid, 'SigM(Sid)')

    # ---------- STEP 3 ------------
    printStep(3)

    # PI
    card_n = '4929837308568547'
    card_exp = '03/23'
    c_code = '725919'
    amount = '130'
    nc = get_random_bytes(4)
    m = 'M221'

    PI = {'card_n': card_n, 'card_exp': card_exp, 'c_code': c_code, 'sid': sid, 'amount': amount,
          'pubKC': pubKC.export_key('DER'),
          'nc': nc, 'm': m}

    print('PI:')
    pprint.pprint(PI)

    # Make SigC(PI)
    sigc_pi = crypto_utils.makeSignature(pvKC, str(PI).encode())
    print('Signature of Customer on (PI) = ', sigc_pi)

    # Generate session AES key
    k = get_random_bytes(16)
    print('Generated (session key):', k)

    # Encrypt PI and SigC(PI) with PubKPG
    print('Encrypting PI and SigC(PI) with PubKPG...')
    k_enc, PI_enc = crypto_utils.hybridEncrypt(k, pubKPG, str(PI).encode())
    k_enc2, sigc_pi_enc = crypto_utils.hybridEncrypt(k, pubKPG, str(sigc_pi).encode())

    # Make PM from PI and SigC(PI)
    PM = {'pi': PI_enc, 'sigc_pi': sigc_pi_enc, 'k': k_enc}
    print('PM:')
    pprint.pprint(PM)

    # Make PO and Sig(OrderDesc,Sid,Amount,NC)
    order_desc = 'ProductID:812'

    PO_aux = {'order_desc': order_desc, 'sid': sid, 'amount': amount, 'nc': nc}
    sigc_po = crypto_utils.makeSignature(pvKC, str(PO_aux).encode())

    PO = {'order_desc': order_desc, 'sid': sid, 'amount': amount, 'nc': nc,
          'sigc_po': sigc_po}

    print('PO:')
    pprint.pprint(PO)

    # Generate session AES key
    k2 = get_random_bytes(16)
    print('Generated (session key 2):', k2)

    # Encrypt PM and PO with PubKM
    print('Encrypting PM and PO with PubKM...')
    k2_enc, PM_enc = crypto_utils.hybridEncrypt(k2, pubKM, str(PM).encode())
    k2_enc2, PO_enc = crypto_utils.hybridEncrypt(k2, pubKM, str(PO).encode())

    step3_dict = {'PM': PM_enc, 'PO': PO_enc, 'k': k2_enc}

    # Send encrypted PM and PO to Merchant
    sendData(merchantSock, step3_dict)

    # ---------- STEP 6 ------------
    printStep(6)

    # Get encrypted Resp,Sid,SigPG(Resp,Sid,Amount,NC) from PG
    step6_dict = recvData(merchantSock)

    # Decrypt
    k_enc3 = step6_dict.get('k')
    resp_enc = step6_dict.get('resp')
    sid_enc = step6_dict.get('sid')
    sigpg_enc = step6_dict.get('sigpg')

    # Used decode on resp because it needs to be string, not bytes
    resp = crypto_utils.hybridDecrypt(k_enc3, pvKC, resp_enc).decode()
    sid = crypto_utils.hybridDecrypt(k_enc3, pvKC, sid_enc)
    sigpg = crypto_utils.hybridDecrypt(k_enc3, pvKC, sigpg_enc)

    print('Decrypted (Resp):', resp)
    print('Decrypted (Sid):', sid)
    print('Decrypted (SigPG):', sigpg)

    # Verify SigPG(Resp,Sid,Amount,NC)
    sigpg_aux = {'resp': resp, 'sid': sid, 'amount': amount, 'nc': nc}
    crypto_utils.verifySignature(pubKPG, str(sigpg_aux).encode(), sigpg, 'SigPG(Resp,Sid,Amount,NC)')

    break
