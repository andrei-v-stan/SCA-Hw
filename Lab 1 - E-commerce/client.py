import os
import threading
import socket
from datetime import datetime
from cripting import *
from card_info import *

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = '192.168.100.2'
port = 20777
client.connect((host, port))


def create_card_info(cardNum, cardExp, cCode, sid, amt, publicC, nonce, idM):
    PI = PaymentInformation(cardNum, cardExp, cCode, sid, amt, publicC, nonce, idM)
    return PI


def create_payment_order(orderDesc, sid, amt, nonce):
    PO = PaymentOrder(orderDesc, sid, amt, nonce)
    return PO


def client_Steps():
    while True:
        try:
            message = input("Input the command : ")
            client.send(message.encode('latin-1'))
            match message:
                case 'execute':
                    print("Step 0:")

                    publicM = RSA.importKey(client.recv(1028), passphrase=None)
                    publicPG = RSA.importKey(client.recv(1028), passphrase=None)

                    # pas1
                    print("Step 1:")

                    keys = keyGen()
                    publicC = keys[0]
                    privateC = keys[1]

                    encdecKey = os.urandom(16)
                    nonce = os.urandom(4)

                    encryptedMessage = encryptAES(publicC.public_key().export_key(), encdecKey, nonce)
                    encryptedMessage = hybridEncryption(encryptedMessage, publicM)
                    client.send(bson.encode(encryptedMessage))

                    keyNonce = encdecKey + b'@@' + nonce
                    client.send(keyNonce)

                    # pas2
                    print("Step 2:")

                    encryptedMessage = client.recv(4096)
                    encryptedMessage = bson.decode(encryptedMessage)

                    encryptedMessage = hybridDecription(encryptedMessage, privateC)
                    sid1, sig = encryptedMessage['dec_text'].split(b'&&')

                    sid = sid1

                    vf = publicSignVf(sid, publicM, sig)
                    if vf == 1:
                        print("The signature is valid")
                    else:
                        print("The signature is invalid ... now stopping")
                        return 0

                    # pas3
                    print("Step 3:")

                    cardNum = input("Enter a card number : ")
                    cardNum = int(cardNum)
                    while cardNum < 10000000 or cardNum >= 10000000000000000000:
                        cardNum = input(
                            "The card must have between 8 and 19 digits, please re-enter the card number : ")
                        cardNum = int(cardNum)

                    cardExp = input("Enter the expiration |month/year| : ")
                    today = datetime.today()
                    ExpM = int(cardExp[:-5])
                    ExpY = int(cardExp[3:])
                    while ExpY < today.year or (ExpY == today.year and ExpM <= today.month):
                        cardExp = input("Please enter a valid expiration |month/year| : ")
                        ExpM = int(cardExp[:-5])
                        ExpY = int(cardExp[3:])

                    cCode = input("Enter the generated OTP confirmation code : ")
                    cCode = int(cCode)
                    while cCode < 100000 or cCode >= 100000000:
                        cCode = input("The code must between 6 and 8 digits, please re-enter the otp code : ")
                        cCode = int(cCode)

                    amt = input("Enter the payment amount : ")
                    idM = client.recv(1024)

                    PI = create_card_info(cardNum, cardExp, cCode, sid, amt, publicC, nonce, idM)
                    bsonPI = PI.encode_info()
                    sigPI = privateSigning(bsonPI, privateC)

                    PM = bsonPI + b' ' + sigPI
                    encryptedMessage = hybridEncryption(PM, publicPG)

                    orderDesc = 'Order description'
                    PO = create_payment_order(orderDesc, sid, amt, nonce)
                    bsonPO = PO.encode_info()
                    sigPO = privateSigning(bsonPO, privateC)

                    PO.set_sigC(sigPO)
                    encodedPO = PO.encode_all_info()

                    encryptedMessage = PM + b'&&' + encodedPO
                    encryptedMessage = hybridEncryption(encryptedMessage, publicM)
                    client.send(bson.encode(encryptedMessage))

                    client.settimeout(5.0)
                    verif = client.recv(1024)
                    client.settimeout(None)

                    if verif == b'go':
                        verif = b'confirm'
                        client.send(verif)

                        # pas6
                        print("Step 6:")

                        encryptedMessage = client.recv(4096)
                        encryptedMessage = bson.decode(encryptedMessage)

                        decryptedMessage = hybridDecription(encryptedMessage, privateC)

                        newEncryptedMessage = decryptedMessage['dec_text']
                        newResponse, newSidPG, newSigPG = newEncryptedMessage.split(b'&&')

                        newEncryptedMessage = client.recv(4096)
                        vf = publicSignVf(newEncryptedMessage, publicPG, newSigPG)

                        if vf == 1:
                            print("The signature is valid")
                        else:
                            print("The signature is invalid ... now stopping")
                            return 0

                case 'end':
                    print("Now exiting...")
                    client.close()
                    return 0



        except Exception as e:

            if e.__class__ == TimeoutError:

                verif = b'timeout'
                client.send(verif)

                # pas7
                print("Step 7:")

                gatewayMessage = str(sid).encode('utf-8') + b' ' + str(PO.get_amount()).encode('utf-8') + b' ' + str(PO.get_nonce()).encode('utf-8') + b' ' + publicC.export_key()

                signedMessage = privateSigning(gatewayMessage, privateC)
                gatewayMessage += b'&&' + signedMessage

                encMessage = hybridEncryption(gatewayMessage, publicPG)
                client.send(bson.encode(encMessage))

                # pas 8
                print("Step 8:")
                encrMessage = client.recv(4096)
                encrMessage = bson.decode(encrMessage)

                decrMessage = hybridDecription(encrMessage, privateC)
                info, sig = decrMessage['dec_text'].split(b'&&')

                gatewayMessage = client.recv(4096)

                vf = publicSignVf(gatewayMessage, publicPG, sig)
                if vf == 1:
                    print("The signature is valid")
                else:
                    print("The signature is invalid ... now stopping")
                    return 0

                print("Finished all steps.")
                return 0

            else:
                client.close()
                break


if __name__ == "__main__":
    send_thread = threading.Thread(target=client_Steps)
    send_thread.start()
