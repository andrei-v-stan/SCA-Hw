import os
import threading
import socket

from cripting import *
from card_info import *

host = '192.168.100.2'
port = 20777

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

clients = []

def client_Rmv(client):
    if client in clients:
        clients.remove(client)
    client.close()


def server_Steps(client):
    while True:
        try:
            message = client.recv(1024).decode('latin-1')
            match message:
                case 'execute':
                    print("Step 0:")

                    keys = keyGen()
                    publicM = keys[0]
                    privateM = keys[1]

                    keys = keyGen()
                    publicPG = keys[0]
                    privatePG = keys[1]

                    client.send(publicM.exportKey(format='PEM', passphrase=None))
                    client.send(publicPG.exportKey(format='PEM', passphrase=None))

                    # pas1
                    print("Step 1:")

                    encryptedMessage = client.recv(4096)
                    encryptedMessage = bson.decode(encryptedMessage)
                    msg = hybridDecription(encryptedMessage, privateM)
                    keyNonce = client.recv(1024)
                    encdecKey, nonce = keyNonce.split(b'@@')

                    publicC = decryptAES(msg['dec_text'], encdecKey, nonce)
                    publicC = RSA.importKey(publicC)

                    # pas2
                    print("Step 2:")

                    sid = os.urandom(3)
                    sig = privateSigning(sid, privateM)

                    encryptedMessage = sid + b'&&' + sig
                    encryptedMessage = hybridEncryption(encryptedMessage, publicC)
                    client.send(bson.encode(encryptedMessage))

                    # pas3
                    print("Step 3:")

                    idM = os.urandom(5)
                    client.send(idM)

                    encryptedMessage = client.recv(4096)
                    encryptedMessage = bson.decode(encryptedMessage)

                    encryptedMessage = hybridDecription(encryptedMessage, privateM)
                    PM, PO = encryptedMessage['dec_text'].split(b'&&')

                    decryptedPO = bson.decode(PO)

                    newPO = PaymentOrder(decryptedPO['orderDesc'], decryptedPO['sid'], decryptedPO['amount'],
                                         decryptedPO['nonce'])

                    vf = publicSignVf(newPO.encode_info(), publicC, decryptedPO['sigC'])
                    if vf == 1:
                        print("The signature is valid")
                    else:
                        print("The signature is invalid ... now stopping")
                        return 0

                    # pas 4
                    print("Step 4:")

                    sidPM = str(newPO.get_sid())
                    amount = str(newPO.get_amount())

                    encryptedMessagePM = sidPM.encode('utf-8') + b' ' + publicC.export_key() + b' ' + amount.encode(
                        'utf-8')
                    sigM = privateSigning(encryptedMessagePM, privateM)

                    enMessage = PM + b'&&' + sigM
                    enMessage = hybridEncryption(enMessage, publicPG)

                    decryptedMessage = hybridDecription(enMessage, privatePG)

                    newPM, newSigM = decryptedMessage['dec_text'].split(b'&&')
                    vf = publicSignVf(encryptedMessagePM, publicM, newSigM)
                    if vf == 1:
                        print("The signature is valid")
                    else:
                        print("The signature is invalid ... now stopping")
                        return 0

                    # pas 5
                    print("Step 5:")

                    response = '1'
                    nonce = str(newPO.get_nonce())

                    encryptedMessagePG = response.encode('utf-8') + b' ' + sidPM.encode('utf-8') + b' ' + amount.encode(
                        'utf-8') + b' ' + nonce.encode('utf-8')
                    sigPG = privateSigning(encryptedMessagePG, privatePG)

                    pgMessage = response.encode('utf-8') + b'&&' + sidPM.encode('utf-8') + b'&&' + sigPG
                    pgMessage = hybridEncryption(pgMessage, publicM)

                    decryptedMessage = hybridDecription(pgMessage, privateM)

                    newResponse, newSidPG, newSigPG = decryptedMessage['dec_text'].split(b'&&')

                    vf = publicSignVf(encryptedMessagePG, publicPG, newSigPG)
                    if vf == 1:
                        print("The signature is valid")
                    else:
                        print("The signature is invalid ... now stopping")
                        return 0

                    while True:
                     x = 1

                    verif = b'go'
                    client.send(verif)

                    verif = client.recv(1024)

                    if verif == b'confirm':

                        # pas 6
                        print("Step 6:")

                        pgMessage2 = response.encode('utf-8') + b'&&' + sidPM.encode('utf-8') + b'&&' + sigPG

                        newEncryptedMessage = hybridEncryption(pgMessage2, publicC)

                        client.send(bson.encode(newEncryptedMessage))

                        client.send(encryptedMessagePG)

                    elif verif == b'timeout':

                        # pas7
                        print("Step 7:")

                        encMessage = client.recv(4096)
                        encMessage = bson.decode(encMessage)

                        decMessage = hybridDecription(encMessage, privatePG)
                        info, signed = decMessage['dec_text'].split(b'&&')

                        vf = publicSignVf(info, publicC, signed)
                        if vf == 1:
                            print("The signature is valid")
                        else:
                            print("The signature is invalid ... now stopping")
                            return 0

                        # pas 8
                        print("Step 8:")
                        response = '1'
                        gatewayMessage = response.encode('utf-8') + b' ' + str(newPO.get_sid()).encode('utf-8')

                        gatewayMessage2 = response.encode('utf-8') + b' ' + str(newPO.get_sid()).encode('utf-8') + b' ' + str(newPO.get_amount()).encode('utf-8') + b' ' + str(newPO.get_nonce()).encode('utf-8')

                        signedMessage = privateSigning(gatewayMessage2, privatePG)
                        gatewayMessage += b'&&' + signedMessage

                        encrMessage = hybridEncryption(gatewayMessage, publicC)
                        client.send(bson.encode(encrMessage))
                        client.send(gatewayMessage2)

                    print("Finished all steps.")

                case 'end':
                    client_Rmv(client)


        except Exception as e:

            if e.__class__ == TimeoutError:
                print(e)

            else:
                print(e.__class__)
                client_Rmv(client)
                client.close()
                break


def client_Data():
    print('\n[Start-up]: The server is now online \n')
    while True:
        print('\n[Info]: Waiting for a client ... ')
        client, address = server.accept()
        processClient = "[Client] : A connection has been established with "
        processClient = processClient + str(address)
        print(processClient)
        clients.append(client)

        thread = threading.Thread(target=server_Steps, args=(client,))
        thread.start()


if __name__ == "__main__":
    client_Data()
