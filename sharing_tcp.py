"""Data access wrapper interface for sharing that uses the TCP server"""

from sharing       import AccessWrapper, AES_dec, AES_enc
from tcp_client    import Server
from Crypto.Cipher import AES
from Crypto        import Random

class TCPAccessWrapper(AccessWrapper):
    def __init__(self, server: Server):
        self.server = server
        self.use_json = True

    def storage_cost(self):
        tables = self.get_tables()
        res = 0
        for t in tables:
            res += len(tables[t])
        return res

    def list_tables(self):
        return list(self.get_tables().keys())

    def load_table(self, name):
        tables = self.get_tables()
        if name not in tables:
            return None
        else:
            return tables[name]

    def upload_table(self, name, table):
        tables = self.get_tables()
        if tables is None:
            tables = {}
        tables[name] = table
        tables = self.serialize(tables)
        return self.server.set("sharing_tables", tables)

    def load_file_iv(self, file_name):
        data = self.server.get(file_name)
        if data is None: return None
        return data[:AES.block_size]

    def file_exists(self, file_name):
        return self.server.exists(file_name)

    def reupload_file(self, su, file_name):
        data = self.server.get(file_name) # load
        if data is None: return None
        iv = data[:AES.block_size]
        key = su.key_gen(iv)
        data = AES_dec(data, key) # decrypt
        data = AES_enc(data, key) # re-encrypt with a new iv
        return self.server.set(file_name, data)

    # extras

    def get_tables(self):
        return self.deserialize(self.server.get("sharing_tables")) or {}

    def load_file(self, su, file_name):
        data = self.server.get(file_name)
        if data is None: return None
        iv = data[:AES.block_size]
        key = su.key_gen(iv)
        return AES_dec(data, key)

    def upload_file(self, su, file_name, new_data):
        data = self.server.get(file_name) # load
        if data is None: # new file
            iv = Random.new().read(AES.block_size)
        else:            
            iv = data[:AES.block_size]
        key = su.key_gen(iv)
        enc = AES_enc(new_data, key, iv) # encrypt with a new iv (or the old)
        return self.server.set(file_name, enc)
