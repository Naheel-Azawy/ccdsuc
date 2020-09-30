"""BlockChain PKI. Intefaces with the CA"""

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
                    "\n-----END PUBLIC KEY-----"
                return RSA.import_key(key)
        return None

    def list_devices(self):
        certs = self.ca.get_certs()
        res = []
        for cert in certs:
            res.append(cert["subject_id"])
        return res

    def add_device(self, device_id: str,
                   device_passphrase: str,
                   valid_to: str):
        key = stringify_keys(gen_keys_from(device_passphrase))["pub"].split("\n")
        del key[0]
        del key[-1]
        key = "\n".join(key)
        return self.ca.enroll({
            "valid_to": valid_to,
            "subject_id": device_id,
            "public_key": key
        })

if __name__ == "__main__":
    import sys
    import os
    import json

    def usage():
        print("usage: python pki_bc.py COMMAND [ARGS]")
        print("")
        print("COMMANDS")
        print(" python pki_bc.py ls")
        print(" python pki_bc.py certs")
        print(" python pki_bc.py get DEVICE_ID")
        print(" python pki_bc.py add DEVICE_ID PASSPHRASE VALID_TO")
        exit(1)

    args = sys.argv

    if len(args) < 2: usage()

    del args[0]
    cmd = args[0]
    del args[0]

    if cmd == "ls":
        pki = BCPKI()
        pki.init()
        print(pki.list_devices())
    elif cmd == "get":
        pki = BCPKI()
        pki.init()
        if len(args) < 1: usage()
        print(pki.get_key(args[0]).export_key("PEM").decode())
    elif cmd == "add":
        pki = BCPKI()
        pki.init()
        if len(args) < 3: usage()
        print(pki.add_device(args[0], args[1], args[2]))
    elif cmd == "certs":
        pki = BCPKI()
        pki.init()
        print(json.dumps(pki.ca.get_certs(), indent=2))
    elif cmd == "deploy":
        os.system("cd ./bcpki && truffle migrate --compile-all --reset")
    else:
        usage()
