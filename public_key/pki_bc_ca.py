"""Certificate Authority. Based on Ethereum blockchain."""

from web3 import Web3
import json
import os
import hashlib

CA_JSON = "./bcpki/build/contracts/CA.json"
#DEF_ADDR = "http://127.0.0.1:8545@0x3BdF8A6a7716D772A2cf7b6183678D005Ee00Ad9"
DEF_ADDR = "http://127.0.0.1:8545@"

class CA:
    """Certificate Authority"""
    def __init__(self):
        env_addr              = os.getenv("ETH_ADDR") or DEF_ADDR
        env_addr              = env_addr.split("@")
        self.url              = env_addr[0]
        self.contract_address = env_addr[1]

    def connect(self):
        """Connect to the blockchain"""
        self.w3 = Web3(Web3.HTTPProvider(self.url))
        
        # the account we use is either from the env of the first account
        self.account = os.getenv("ETH_ACCOUNT") or self.w3.eth.accounts[0]
        self.w3.eth.defaultAccount = self.account

        # read the ABI and bytecode of the contract
        with open(CA_JSON) as f:
            j        = json.loads(f.read())
            abi      = j["abi"]
            bytecode = j["bytecode"]

        # if we don't have the contract address, we deploy it and get the address
        # https://ethereum.stackexchange.com/questions/12859/get-deployed-contract-from-web3
        if not self.contract_address:
            CA            = self.w3.eth.contract(abi=abi, bytecode=bytecode)
            tx_hash       = CA.constructor().transact()
            tx_receipt    = self.w3.eth.waitForTransactionReceipt(tx_hash)
            self.contract_address = tx_receipt.contractAddress
            print(f"Contract deployed. Transaction hash = {tx_hash.hex()}")

        # create an instance of the contract
        self.contract = self.w3.eth.contract(address=self.contract_address, abi=abi)
        print(f"Contract address = {self.contract.address}")

        return self.w3.isConnected()

    def gen_hash(cert):
        """Generate a hash of the certificate dict.
        If `cert` is the hash, return it.
        This allows passing either the hash or the cert
        itself in the functions below"""
        if isinstance(cert, str):
            return cert
        return hashlib.sha256((cert["valid_to"] +
                               cert["public_key"] +
                               cert["subject_id"])
                              .encode()).hexdigest()

    def build_dicts(tuples):
        """Translate arrays to tuples to arrays of dicts"""
        res = []
        for t in tuples:
            res.append({
                "version": t[0],
                "valid_to": t[1],
                "public_key": t[2],
                "issuer_id": t[3],
                "subject_id": t[4],
                "exist": t[5],
                "wallet_owner": t[6]
            })
        return res

    def enroll(self, cert):
        """Enroll a certificate"""
        tx_hash = self.contract.functions.enroll(CA.gen_hash(cert),
                                                 cert["valid_to"],
                                                 cert["public_key"],
                                                 cert["subject_id"]).transact()
        tx_receipt = self.w3.eth.waitForTransactionReceipt(tx_hash)
        return tx_hash.hex()

    def revoke(self, cert):
        """Revoke a certificate. Pass the certificate dict or the hash"""
        tx_hash = self.contract.functions.revoke(CA.gen_hash(cert)).transact()
        tx_receipt = self.w3.eth.waitForTransactionReceipt(tx_hash)
        return tx_hash.hex()

    def verify(self, cert):
        """Verify a certificate. Pass the certificate dict or the hash"""
        return self.contract.functions.verify(CA.gen_hash(cert)).call()

    def get_certs(self):
        """Get valid certificates"""
        return CA.build_dicts(self.contract.functions.get_certs().call())

    def get_all_certs(self):
        """Get all certificates including invalid ones"""
        return CA.build_dicts(self.contract.functions.get_all_certs().call())

    def get_crl(self):
        """Get the Certificate Revocation List"""
        return CA.build_dicts(self.contract.functions.get_crl().call())

def ca_test():
    the_cert = {
        "valid_to": "2030-09-26",
        "public_key": "aaaaaaaaaaaaaa",
        "subject_id": "me"
    }
    the_other_cert = {
        "valid_to": "2030-09-26",
        "public_key": "cccccccccccccccc",
        "subject_id": "myself"
    }
    ca = CA()
    print(ca.connect())
    print(ca.enroll(the_cert))
    print(ca.enroll(the_other_cert))
    print(ca.get_certs())
    print(ca.verify(the_other_cert) == True)
    print(ca.revoke(the_other_cert))
    print(ca.get_certs())
    print(ca.verify(the_other_cert) == False)

def ca_test_2():
    the_cert = {
        "valid_to": "2030-09-26",
        "public_key": """MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA01ShzNMsEE8/PZ1QY9RB
WjkC20qp/KEGkN5QWjKCpBgk8t6oy1qH1c4T2/FlwywF8ldLrsC5fuCVltyNfEZ3
7Qpr+khM9vdO2ZIq0vKyXgN5/ol87o1KemLLIZHdcrfMyhU6xwwUeIkhrMUfDVin
Bhvk7dSv25LbrNJDvEO7mLGgtxgmvc+C0V8IZonoKUE0+PUecgkkqX55+sip/ZCI
SltqexJMxISMd0eGbGIMrauZPZNBw4zOEvDvY+xxPUfs9xdtk7bIjb0QHg9SjtHJ
R/o26p285Ks72c1qF1wfHjdSsOeq0xorvEi6YVTloTsOHShtJd/1nBoGqgwQFxcH
gwIDAQAB""",
        "subject_id": "me"
    }
    ca = CA()
    print(ca.connect())
    print(ca.enroll(the_cert))
    print(ca.get_certs())
    print(ca.verify(the_cert))

#ca_test_2()
