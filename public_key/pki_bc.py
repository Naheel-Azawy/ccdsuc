"""BlockChain PKI. Intefaces with the CA"""

from public_key.pki_base import PKI
from core.sharing        import gen_keys_from, stringify_keys, PublicKey

import subprocess
import time
import re

GANACHE = "ganache-cli --host 0.0.0.0 --port 8545"
DEPLOY  = "cd ./public_key/bcpki && truffle migrate --compile-all --reset"

class BCPKI(PKI):
    """BlockChain PKI"""
    def init(self):
        from public_key.pki_bc_ca import CA
        self.ca = CA()
        self.ca.connect()

    def get_key(self, user_id: str):
        certs = self.ca.get_certs()
        for cert in certs:
            if cert["subject_id"] == user_id:
                key = "-----BEGIN PUBLIC KEY-----\n" + \
                    cert["public_key"] + \
                    "\n-----END PUBLIC KEY-----"
                return PublicKey.import_key(key)
        return None

    def list_ids(self):
        certs = self.ca.get_certs()
        res = []
        for cert in certs:
            res.append(cert["subject_id"])
        return res

    def enroll(self, user_id: str, passphrase: str, valid_to: str):
        key = stringify_keys(gen_keys_from(passphrase))["pub"].split("\n")
        del key[0]
        del key[-1]
        key = "\n".join(key)
        return self.ca.enroll({
            "valid_to": valid_to,
            "subject_id": user_id,
            "public_key": key
        })

    def revoke(self, user_id):
        certs = self.ca.get_certs()
        for cert in certs:
            if cert["subject_id"] == user_id:
                return self.ca.revoke(cert)
        return None

def deploy():
    popen = subprocess.Popen(["sh", "-c", DEPLOY],
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
    deploying_ca = False
    ca_address = None
    for line in iter(popen.stdout.readline, ""):
        if "Deploying 'CA'" in line:
            deploying_ca = True
        elif deploying_ca and "contract address:" in line:
            ca_address = line.strip()
        print("truffle: " + line.rstrip())

    try:
        ca_address = re.search('.+:\s+(.+)', ca_address).group(1)
        return f"http://localhost:8545@{ca_address}"
    except:
        return None

def main(args):
    import os
    import json

    def usage():
        print("control the blockchain PKI from the command-line.")
        print("make sure an Ethereum blockchain is running, e.g.")
        print(" $ ganache-cli --host 0.0.0.0 --port 8545")
        print("and the address is exported as")
        print(" $ export ETH_ADDR='http://<IP>:<PORT>@<CONTRACT_ADDRESS>'")
        print("")
        print("COMMANDS:")
        print("  deploy        deploy truffle contracts")
        print("  demo          start ganache, deploy, and add demo users")
        print("  ls            list IDs")
        print("  certs         list certificates")
        print("  get <ID>      get the user's public key")
        print("  add <ID> <PASSPHRASE> <VALID_TO> enroll a new user")
        print("  revoke <ID>   revoke a user")

    if len(args) < 2:
        usage()
        return 1

    del args[0]
    cmd = args[0]
    del args[0]

    if cmd == "ls":
        pki = BCPKI()
        pki.init()
        print(pki.list_ids())
    elif cmd == "get":
        pki = BCPKI()
        pki.init()
        if len(args) < 1:
            usage()
            return 1
        print(pki.get_key(args[0]).export_key("PEM").decode())
    elif cmd == "add":
        pki = BCPKI()
        pki.init()
        if len(args) < 3:
            usage()
            return 1
        print(pki.enroll(args[0], args[1], args[2]))
    elif cmd == "revoke":
        pki = BCPKI()
        pki.init()
        if len(args) < 1:
            usage()
            return 1
        print(pki.revoke(args[0]))
    elif cmd == "certs":
        pki = BCPKI()
        pki.init()
        print(json.dumps(pki.ca.get_certs(), indent=2))
    elif cmd == "deploy":
        addr = deploy()
        if addr is None:
            print("failed finding the contract address")
        else:
            print("export the contract address as follows:")
            print(f"$ export ETH_ADDR='{addr}'")
    elif cmd == "demo":
        # start ganache in the background
        os.system(GANACHE + " &")
        time.sleep(5)

        # deploy
        addr = deploy()

        print("")
        if addr is None:
            print("failed finding the contract address")
        else:
            os.environ["ETH_ADDR"] = addr

            # add demo users
            pki = BCPKI()
            pki.init()
            users = [("alice", "123"), ("bob", "abc"),
                     ("piled", "led"), ("pildr", "ldr"),
                     ("naheel", "deadbeef"), ("notnaheel", "foobar")]
            for u in users:
                print(f">>> adding user {u}...")
                print(pki.enroll(u[0], u[1], "3030-03-03"))

            print("export the contract address as follows:")
            print(f"$ export ETH_ADDR='{addr}'")
    elif cmd == "keys-pv":
        if len(args) < 1:
            usage()
            return 1
        keys = stringify_keys(gen_keys_from(args[0]))
        for k in keys:
            print(k + ":")
            print(keys[k])
            print("")
    else:
        usage()
        return 1
