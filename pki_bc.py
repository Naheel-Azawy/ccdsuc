from pki              import PKI
from pki_ca           import CA
from sharing          import gen_keys_from, stringify_keys
from Crypto.PublicKey import RSA

class BCPKI(PKI):
    """BlockChain PKI"""
    def init(self):
        self.ca = CA()
        self.ca.connect()

    def get_key(self, device_id: str):
        certs = self.ca.get_certs()
        for cert in certs:
            if cert["subject_id"] == device_id:
                key = "-----BEGIN PUBLIC KEY-----\n" + \
                    cert["public_key"] + \
                    "-----END PUBLIC KEY-----"
                return RSA.import_key(key)                
        return None

    def add_device(self, device_id: str,
                   device_passphrase: str,
                   valid_to: str):
        key = stringify_keys(gen_keys_from(device_passphrase))["pub"].split("\n")
        del key[0]
        del key[-1]
        key = "\n".join(key)
        self.ca.enroll({
            "valid_to": valid_to,
            "subject_id": device_id,
            "public_key": key
        })
