"""Public Key Infrastructure base interface"""

from sharing import gen_keys_from

class PKI:
    """Public Key Infrastructure interface"""
    def init(self):
        pass

    def get_key(self, device_id: str):
        raise Exception("Not implemented")

    def add_device(self, device_id: str,
                   device_passphrase: str,
                   valid_to: str):
        raise Exception("Not implemented")

class FakePKI(PKI):
    """Fake PKI"""

    def get_key(self, device_id: str):
        return gen_keys_from("123")["pub"]

    def add_device(self, device_id: str,
                   device_passphrase: str,
                   valid_to: str):
        pass
