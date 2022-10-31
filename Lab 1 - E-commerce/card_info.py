import bson


class PaymentOrder:
    def __init__(self, orderDesc, sid, amount, nonce):
        self.body = {
            "orderDesc": orderDesc,
            "sid": sid,
            "amount": amount,
            "nonce": nonce,
            "sigC": None
        }

    def set_sigC(self, sigC):
        self.body['sigC'] = sigC

    def get_attributes(self):
        return {i: self.body[i] for i in self.body if i != 'sigC'}

    def get_all_attributes(self):
        return {i: self.body[i] for i in self.body}

    def get_sigC(self):
        return self.body['sigC']

    def encode_info(self):
        return bson.encode(self.get_attributes())

    def encode_all_info(self):
        return bson.encode(self.get_all_attributes())

    def get_amount(self):
        return self.body['amount']

    def get_sid(self):
        return self.body['sid']

    def get_nonce(self):
        return self.body['nonce']

class PaymentInformation:
    def __init__(self, cN, cE, cC, sid, amount, pubkC, nonce, id):
        self.body = {
            "cardNumber": cN,
            "cardExp": cE,
            "cCode": cC,
            "sid": sid,
            "amount": amount,
            "pubkC": pubkC,
            "nonce": nonce,
            "idMerchant": id
        }

    def get_attributes(self):
        return {i: self.body[i] for i in self.body if i != 'pubkC'}

    def encode_info(self):
        return bson.encode(self.get_attributes())


class Card:
    def __init__(self):
        self.body = {
            "cardNumber": 0,
            "cardExp": 0,
            "cCode": 0
        }
