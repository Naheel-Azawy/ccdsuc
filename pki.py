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
