"""The implementation of the secure key sharing"""

import random
import hashlib
import secrets
import base64
import pickle
import json
from Crypto              import Random
from Crypto.Cipher       import AES, PKCS1_OAEP
from Crypto.PublicKey    import RSA
from Crypto.Util.Padding import pad, unpad

# https://pycryptodome.readthedocs.io/en/latest/src/examples.html
# https://gist.github.com/syedrakib/241b68f5aeaefd7ef8e2
# https://docs.python.org/3/library/random.html
# https://www.pycryptodome.org/en/latest/src/public_key/rsa.html?highlight=rsa#module-Crypto.PublicKey.RSA

# generate: AES key, RSA private key, RSA public key
# from a passphrase

def gen_keys_from(passphrase):

    # symmetric key used for AES

    k_sym = hashlib.sha256(passphrase.encode()).digest()

    # for RSA, we seed the RNG with the passphrase and
    # give the RNG to RSA generator

    random.seed(passphrase)

    def my_rand(nbytes):
        return bytearray(random.getrandbits(8)
                         for _ in range(nbytes))

    k_priv = RSA.generate(2048, my_rand)
    k_pub  = k_priv.publickey()

    return { "sym": k_sym, "priv": k_priv, "pub": k_pub }

def stringify_keys(keys):
    return {
        "sym":  base64.b64encode(keys["sym"]).decode(),
        "priv": keys["priv"].export_key('PEM').decode(),
        "pub":  keys["pub"].export_key('PEM').decode()
    }

def unstringify_keys(str_keys):
    return {
        "sym":  base64.b64decode(str_keys["sym"].encode()),
        "priv": RSA.import_key(str_keys["priv"]),
        "pub":  RSA.import_key(str_keys["pub"])
    }

# tiny cyphers

def AES_enc(data, key, iv=None):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ciphertext

def AES_dec(data, key):
    iv = data[:AES.block_size]
    ciphertext = data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

def RSA_enc(data, key):
    session_key = secrets.token_bytes(nbytes=int(AES.key_size[-1]))

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(key)
    session_key_enc = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    ciphertext = AES_enc(data, session_key)
    return session_key_enc + ciphertext

def RSA_dec(data, key):
    session_key_enc = data[:AES.key_size[-1] * 8]
    ciphertext = data[AES.key_size[-1] * 8:]

    # Decrypt the session key
    cipher_rsa = PKCS1_OAEP.new(key)
    session_key = cipher_rsa.decrypt(session_key_enc)

    # Decrypt the data
    return AES_dec(ciphertext, session_key)

# json

def isbase64(s):
    # https://stackoverflow.com/a/45928164/3825872
    try:
        return base64.b64encode(base64.b64decode(s)).decode() == s
    except Exception:
        return False

def jsonify(o):
    o = o.copy()
    if isinstance(o, dict):
        for k in o: # because json can't handle bytes
            if isinstance(o[k], bytes):
                o[k] = base64.b64encode(o[k]).decode()
    return json.dumps(o, separators=(',', ':')).encode()

def unjsonify(s):
    o = json.loads(s)
    if isinstance(o, dict):
        for k in o: # because json can't handle bytes
            if isbase64(o[k]):
                o[k] = base64.b64decode(o[k])
    return o

# pickle

def picklize(o):
    return pickle.dumps(o)

def unpicklize(b):
    return pickle.loads(b)

class AccessWrapper(object):
    use_json = False

    def storage_cost(self):
        return 0

    def list_tables(self):
        return []

    def load_table(self, name):
        return None

    def upload_table(self, name, table):
        return False

    def load_file_iv(self, file_name):
        return None

    def file_exists(self, file_name):
        return False

    def reupload_file(self, su, file_name):
        return False

    def name(self, file_name):
        return file_name

    # generic serializer
    def serialize(self, o):
        if o is None:
            return None
        return jsonify(o) if self.use_json else picklize(o)

    # generic deserializer
    def deserialize(self, b):
        if b is None:
            return None
        return unjsonify(b) if self.use_json else unpicklize(b)

class FakeAccessWrapper(AccessWrapper):
    def __init__(self, use_json=False):
        self.use_json = use_json
        self.tables = {}
        self.files  = {}

    def storage_cost(self):
        res = 0
        for t in self.tables:
            res += len(self.tables[t])
        return res

    def list_tables(self):
        return list(self.tables.keys())

    def load_table(self, name):
        if name not in self.tables:
            return None
        else:
            return self.tables[name]

    def upload_table(self, name, table):
        self.tables[name] = table
        return True

    def load_file_iv(self, file_name):
        if file_name not in self.files:
            return None
        return self.files[file_name][:AES.block_size]

    def file_exists(self, file_name):
        return file_name in self.files

    def reupload_file(self, su, file_name):
        data = self.load_fake_file(file_name) # load
        if data is None: return False
        iv = self.load_file_iv(file_name)
        key = su.key_gen(iv)
        data = AES_dec(data, key) # decrypt
        data = AES_enc(data, key) # re-encrypt
        self.files[file_name] = data
        return True

    # fake methods:

    def fake_file(self, su, file_name, data=None, size=512):
        if data == None:
            data = bytearray([i % 256 for i in range(size)])
            iv = Random.new().read(AES.block_size)
            key = su.key_gen(iv)
            data_enc = AES_enc(data, key, iv)
        self.files[file_name] = data_enc
        return data, data_enc

    def load_fake_file(self, file_name):
        if file_name not in self.files:
            return None
        return self.files[file_name]

    # get one of the files from list_files_shared_with_us()
    def load_fake_shared_file(self, su, file_path, key=None):
        data = self.load_fake_file(file_path)

        if key == None:
            key = su.get_shared_file_key(file_path)
            if key is None:
                return None

        data = AES_dec(data, key)
        return data

class SharingUtility(object):
    def __init__(self, user_id, passphrase=None, k_sym=None, k_pub=None, k_priv=None, access_wrapper=None, keys_cache=None):

        if "_" in user_id:
            raise Exception(f"'_' is not allowed in SharingUtility's user_id ({user_id})")
        
        self.user_id = user_id
        self.alice_id = user_id

        keys_read_from_file = False
        if keys_cache is not None:
            try:
                with open(keys_cache, "r") as f:
                    str_keys = json.loads(f.read())
                keys = unstringify_keys(str_keys)
                self.k_alice      = keys["sym"]
                self.k_alice_pub  = keys["pub"]
                self.k_alice_priv = keys["priv"]
                keys_read_from_file = True
            except:
                keys_read_from_file = False

        if not keys_read_from_file:
            if passphrase is not None:
                keys = gen_keys_from(passphrase)
                self.k_alice      = keys["sym"]
                self.k_alice_pub  = keys["pub"]
                self.k_alice_priv = keys["priv"]
            else:
                self.k_alice      = k_sym
                self.k_alice_pub  = k_pub
                self.k_alice_priv = k_priv

        self.keys = {
            "sym":  self.k_alice,
            "pub":  self.k_alice_pub,
            "priv": self.k_alice_priv
        }

        self.keys_str = stringify_keys(self.keys)

        if not keys_read_from_file and keys_cache is not None:
            with open(keys_cache, "w") as f:
                f.write(json.dumps(self.keys_str))

        if access_wrapper == None:
            self.access_wrapper = FakeAccessWrapper()
        else:
            self.access_wrapper = access_wrapper
            try:
                if self.access_wrapper.sharing_utility is None:
                    self.access_wrapper.sharing_utility = self
            except:
                pass

    # k_f = H(f_IV | k_A)
    def key_gen(self, f_IV):
        return hashlib.sha256(f_IV + self.k_alice).digest()

    # files Alice share with others:
    # T_A,others = E({ "B" -> ["f", ...], ... }, k_A)
    # files Alice share with Bob:
    # T_A,B      = E({ "f" -> "k_f", ... },      k_Bpub)

    def load_table(self, bob_id=None):
        name = self.get_table_name(bob_id)
        table = self.access_wrapper.load_table(name)
        if table == None:
            return None

        if bob_id == None:
            # files Alice share with others
            key = self.k_alice
            table = AES_dec(table, key)
        else:
            # files >>>Bob<<< share with Alice
            key = self.k_alice_priv
            table = RSA_dec(table, key)

        table = self.access_wrapper.deserialize(table)
        return table

    def get_table_name(self, bob_id=None, alice_id=None):
        if bob_id == None:
            # files Alice share with others
            name = f"table_{self.alice_id}_others"
        elif alice_id != None:
            # files Alice share with Bob
            name = f"table_{self.alice_id}_{bob_id}"
        else:
            # files >>>Bob<<< share with Alice
            name = f"table_{bob_id}_{self.alice_id}"
        return name

    def upload_table(self, name, table):
        self.access_wrapper.upload_table(name, table)

    # checks is a file is shared with a user
    def is_shared(self, file_name, user):
        file_name = self.access_wrapper.name(file_name)
        users = self.list_files_shared_by_us()
        try:
            files = users[user]
            if file_name in files:
                return True
        except:
            pass
        return False

    # share a file from Alice to Bob
    def share_file(self, file_path, bob_id, k_bob_pub):

        # clean the file name
        file_path = self.access_wrapper.name(file_path)

        # check if the file exists. If not, fail
        if not self.access_wrapper.file_exists(file_path):
            return None, None, None, None

        # load the files shared by Alice with anyone else
        # if does not exist, create new one
        T_A_others = self.load_table() or {}

        # bob already has a table with us
        if bob_id in T_A_others:
            # list of file paths shared with Bob from Alice
            files_shared_with_bob = T_A_others[bob_id]

            # re-construct Bob's table (by Alice)
            T_A_B = {}
            for f in files_shared_with_bob:
                T_A_B[f] = self.key_gen(
                    self.access_wrapper.load_file_iv(f))
        else:
            T_A_B = {}
            T_A_others[bob_id] = []

        # add the new file
        T_A_B[file_path] = self.key_gen(
            self.access_wrapper.load_file_iv(file_path))
        T_A_others[bob_id].append(file_path)

        # serialize
        T_A_B      = self.access_wrapper.serialize(T_A_B)
        T_A_others = self.access_wrapper.serialize(T_A_others)

        # upload T_A_B
        T_A_B_enc = RSA_enc(T_A_B, k_bob_pub)
        self.upload_table(self.get_table_name(
            alice_id=self.alice_id,
            bob_id=bob_id), T_A_B_enc)

        # upload T_A_others
        T_A_others_enc = AES_enc(T_A_others, self.k_alice)
        self.upload_table(self.get_table_name(), T_A_others_enc)

        return T_A_B, T_A_B_enc, T_A_others, T_A_others_enc

    # list files shared with us (alice) from others
    # default:    { "bob": { "file.txt": b"key", ... }, ... }
    # only_files: [ "file.txt", ... ]
    def list_files_shared_with_us(self, only_files=False):
        tables = self.access_wrapper.list_tables()
        bobs = []
        for table in tables:
            sp = table.split("_")
            shared_by = sp[1]
            shared_to = sp[2]
            if shared_to == self.alice_id:
                bobs.append(shared_by)

        if only_files:
            files = []
            for bob in bobs:
                files += list(self.load_table(bob).keys())
            return files
        else:
            sharers = {}
            for bob in bobs:
                sharers[bob] = self.load_table(bob)
            return sharers

    # list files shared by us (alice) to others
    def list_files_shared_by_us(self):
        return self.load_table() or {}

    # get k_f of one of the files from list_files_shared_with_us()
    def get_shared_file_key(self, file_path):

        # clean the file name
        file_path = self.access_wrapper.name(file_path)

        # map sharers to files lists
        sharers = self.list_files_shared_with_us()
        for bob in sharers:
            files = sharers[bob] # files to keys map
            if file_path in files:
                return files[file_path]

        return None

    # revoke bob from accessing a file
    def revoke_shared_file(self, file_path, bob_id, k_bob_pub):

        # clean the file name
        file_path = self.access_wrapper.name(file_path)

        # load the files shared by Alice with anyone else
        T_A_others = self.load_table()
        if T_A_others == None:
            return False

        # we did not share anything with bob before
        if bob_id not in T_A_others:
            return False

        # list of file paths shared with Bob from Alice
        files_shared_with_bob = T_A_others[bob_id]

        # this file is not shared with bob
        if file_path not in files_shared_with_bob:
            return False

        # remove the revoked file from the list
        files_shared_with_bob.remove(file_path)

        # re-construct Bob's table (by Alice)
        T_A_B = {}
        for f in files_shared_with_bob:
            T_A_B[f] = self.key_gen(
                    self.access_wrapper.load_file_iv(f))

        # serialize tables
        T_A_B      = self.access_wrapper.serialize(T_A_B)
        T_A_others = self.access_wrapper.serialize(T_A_others)

        # upload T_A_B
        T_A_B_enc = RSA_enc(T_A_B, k_bob_pub)
        self.upload_table(self.get_table_name(
            alice_id=self.alice_id,
            bob_id=bob_id), T_A_B_enc)

        # upload T_A_others
        T_A_others_enc = AES_enc(T_A_others, self.k_alice)
        self.upload_table(self.get_table_name(), T_A_others_enc)

        # upload the file
        return self.access_wrapper.reupload_file(self, file_path)

    def relative_path(self, file_path):
        return self.access_wrapper.name(file_path)

    def full_path(self, file_path):
        return self.access_wrapper.fullname(file_path)
