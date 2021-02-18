"""Public Key Infrastructure interface"""

from public_key.pki_base import PKI
from core.sharing        import PublicKey

class FakePKI(PKI):
    """Fake PKI"""

    def init(self):
        self.keys = {
            # sharing.gen_keys_from("123")["pub"]
            "alice-sens": """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArglik2sz7U3eYwdde5zK
H8mFIQUiaKZnIzGdhHNIDHyjx8RlobZUpcJwS/5rrNjcn7rhYn4aKkHT5hZoTyQk
9vKhe349xBnL4uUafrvAR69HqtFH098IocjADMUQSTho+J76Mf52tmbCjJsC+Z82
ukyG/v6PDin5CGFywE+H9dAd6vA8CDbxFD0C38Q1VY2uUP1G4FarrCMtUHpajHfn
L5fN2rW7e+rg4pFOTNiVZP4YDj6dSLfOH4AQee/OWwh1z6pDM1Ji+5jMIR3wfFOA
wa2o88UqNONQGX/FaDDN1J7obRvM9es7fHpz3KpQQg5q0BEKP2ddsTZMWXnnCO1h
eQIDAQAB
-----END PUBLIC KEY-----""",
            # sharing.gen_keys_from("abc")["pub"]
            "bob-act": """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp3kpnQ17q9+74fOmkyA5
+mKcvN99zypXjuYgXUDMLXhtqaT9wVlxwuxQ6bn4gp57ImxfTj2wTw3fqfguZ4L4
o03taCczgoA3l7Gh9vDcwL4K5Kk2iEpS4jupFgbhihDkNiDC2ic4I0KTrzFoIpDN
ld0JopnDCCwgdPJv7nwB+jWuOqOwsqZSWJ9RXJuWFIzZa58tt7H3xs5S+yGney8S
iVEF2kyC7coHURsclrbnBIAEY4O6BZXt+UixL0qXeU+HyREAqXq2mPHzA9bcx/cF
+YEuyGs6cqIFvvuPfJREjb9G+yoN9VN+yYZt4FWD+wtGc8JUi3kRkiHF7w0lz5jp
QQIDAQAB
-----END PUBLIC KEY-----"""
        }

    def get_key(self, device_id: str):
        if device_id in self.keys:
            key = self.keys[device_id]
        else:
            key = self.keys["alice-sens"]
        return PublicKey.import_key(key)

    def add_device(self, device_id: str,
                   device_passphrase: str,
                   valid_to: str):
        pass

try:
    import public_key.pki_bc
    pki_interface = public_key.pki_bc.BCPKI
except ImportError:
    print("WRANING: failed importing BCPKI, using fake PKI")
    pki_interface = FakePKI
