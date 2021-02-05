import os
import shutil
import socket
import json
import threading

from errno import EACCES
from fuse  import FuseOSError

from core.sharing   import SharingUtility, AccessWrapper
from public_key.pki import pki_interface
from fs.crypto_fs   import CryptoFS

LOG = True

def log(msg):
    if LOG:
        print(msg)

class FSAccessWrapper(AccessWrapper):
    def __init__(self):
        self.fs = None

    # override
    def storage_cost(self):
        res = 0
        p = self.tables_dir()
        for t in self.list_tables():
            res += os.path.getsize(f"{p}/{t}")
        return res

    # override
    def list_tables(self):
        p = self.tables_dir()
        if p is not None:
            return list(map(lambda abs_path: os.path.basename(abs_path),
                            os.listdir(p)))
        else:
            return []

    # override
    def load_table(self, name):
        p = f"{self.tables_dir()}/{name}"
        if not os.path.exists(p):
            return None
        else:
            with open(p, "rb") as f:
                return f.read()
            return None

    # override
    def upload_table(self, name, table):
        with open(f"{self.tables_dir()}/{name}", "wb") as f:
            f.write(table)
            return True
        return False

    # override
    def load_file_iv(self, file_name):
        p = f"{self.fs.root}/{self.fs.su.user_id}/{file_name}"
        if not os.path.exists(p):
            return None
        with open(p, "rb") as f:
            return f.read(self.fs.block_size)
        return None

    # override
    def file_exists(self, file_name):
        return os.path.exists(f"{self.fs.mount}/{file_name}")

    # override
    def reupload_file(self, su, file_name):
        file_name = f"{self.fs.mount}/{file_name}"
        tmp = f"{file_name}___tmp"
        shutil.copy2(file_name, tmp)
        shutil.move(tmp, file_name)
        return True

    # extra functions

    def tables_dir(self):
        if self.fs is None:
            return None
        p = f"{self.fs.root}/__sharing_tables"
        if not os.path.isdir(p):
            os.makedirs(p)
        return p

class ShareFS(CryptoFS):
    def __init__(self, root, mount, sharing_util):
        super().__init__(root, mount)
        self.su = sharing_util
        self.pki = pki_interface()
        self.unlinked_ivs = {}
        os.makedirs(f"{self.root}/{self.su.user_id}", exist_ok=True)

    # override
    def key_gen(self, path, iv):
        log(f">>> key_gen({path}, {iv})")
        if path.startswith("/shared"):
            log("shared key...")
            path = path.split("/")
            if path[0] == "":
                del path[0]
            bob = path[1] if len(path) >= 2 else None
            if len(path) > 2:
                path = "/".join(path[2:])
                shared = self.su.list_files_shared_with_us()
                log(shared)
                if "/" + path in shared[bob]:
                    path = "/" + path
                if bob in shared and path in shared[bob]:
                    return shared[bob][path]
                else:
                    raise FuseOSError(EACCES)
            else:
                raise FuseOSError(EACCES)
        else:
            log("normal keygen...")
            log(self.su.key_gen(iv))
            return self.su.key_gen(iv)

    # override
    def translate_path(self, path):
        ret = None
        if path.startswith("/shared"):
            shared = self.su.list_files_shared_with_us()
            if path == "/shared":
                ret = self.root + "/" + self.su.user_id + path
            else:
                path = path.split("/")
                if path[0] == "":
                    del path[0]
                bob = path[1] if len(path) >= 2 else None
                if len(path) == 2 and bob in shared:
                    # paths like /shared/bob, just use root/alice/shared attrs
                    ret = f"{self.root}/{self.su.user_id}/shared"
                elif len(path) > 2:
                    path = "/".join(path[2:])
                    ret = f"{self.root}/{bob}/{path}"
                else:
                    raise FuseOSError(EACCES)
        else:
            ret = self.root + "/" + self.su.user_id + path
        return ret

    # override
    def lsdir(self, path):
        real_path = self.translate_path(path)
        if path == "/":
            if not os.path.isdir(f"{real_path}/shared"):
                os.makedirs(f"{real_path}/shared")
        ret = []
        if path.startswith("/shared"):
            shared = self.su.list_files_shared_with_us()
            if path == "/shared":
                ret = list(shared.keys())
            else:
                path = path.split("/")
                if path[0] == "":
                    del path[0]
                bob = path[1] if len(path) >= 2 else None
                if len(path) >= 2:
                    path = "/".join(path[2:])
                    other = os.listdir(f"{self.root}/{bob}/{path}")
                    allowed = list(shared[bob].keys())
                    allowed = list(map(lambda p: p if p[0] != '/' else p[1:],
                                       allowed))
                    ret = []
                    # TODO: handle files shared in subdirectories
                    for f in other:
                        if f in allowed:
                            ret.append(f)
                else:
                    ret = []
        else:
            ret = os.listdir(real_path)
        return ret

    # override
    def unlink(self, path):
        """Some programs unlink the file and create a new
        one while editing. So, we keep the IVs before unlinking
        for shared files in case of need"""
        log(f"!!!!!! unlink({path})")
        origin = path
        path = self.translate_path(path)
        if origin.startswith("/shared"):
            log(f"!!!!-> shared file {origin}, {path}")
            with open(path, "rb") as f:
                log("!!! reading...")
                iv = f.read(self.fs.block_size)
                log(f"!!! iv={iv}")
                self.unlinked_ivs[origin] = iv
                log(self.unlinked_ivs)
                log("!!! unlinking")
                return os.unlink(path)
            raise FuseOSError(EACCES)
        else:
            return os.unlink(path)

    # override
    def read_blocks(self, path, virt_path, size, offset, fh):
        log("!!!!!!!!!!! custom read_blocks")
        plaintext, first_block_num, seq_size, file_size, iv = \
            super().read_blocks(path, virt_path, size, offset, fh)
        if not iv and virt_path in self.unlinked_ivs:
            log(f"!!!!!!!!! found iv for {virt_path}: {iv}")
            iv = self.unlinked_ivs[virt_path]
        return plaintext, first_block_num, seq_size, file_size, iv

    # override
    def fsname(self):
        return f"sharefs:{self.su.user_id}"

    # override
    def start(self):
        self.pki.init()
        return super().start()

    def share(self, file_path, bob):
        k_bob_pub = self.pki.get_key(bob)
        res, _, _, _ = self.su.share_file(file_path, bob, k_bob_pub)
        return res != None

    def revoke(self, file_path, bob):
        return self.su.revoke_shared_file(file_path, bob, self.pki.get_key)

    def ls_shares(self, file_path):
        res = []
        bobs = self.su.list_files_shared_by_us()
        for bob in bobs:
            if file_path in bobs[bob]:
                res.append(bob)
        return res

    def start_server(self):
        BUFFER_SIZE = 1024
        running = True
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("localhost", 0))
        s.listen(1)
        port = s.getsockname()[1]
        print(f"Server started at :{port}")
        while running:
            conn, addr = s.accept()

            # recieving data
            data = b""
            while True:
                tmp = conn.recv(BUFFER_SIZE)
                data += tmp
                if not tmp or data.endswith(b"?END?"): break

            msg = f"Command from {addr}: "
            try:
                data = data.decode().replace("?END?", "")
                data = data.split(" ")
                cmd = data[0]
                bob = data[1] if data[1] != "None" else None
                file_path = " ".join(data[2:])

                if cmd == "share":
                    ret = self.share(file_path, bob)
                    msg += f"share({file_path}, {bob})"
                elif cmd == "revoke":
                    ret = self.revoke(file_path, bob)
                    msg += f"revoke({file_path}, {bob})"
                elif cmd == "ls-shares":
                    ret = self.ls_shares(file_path)
                    msg += f"ls_shares({file_path})"
                else:
                    ret = "unknown"
                    msg += f"unknown command '{cmd}'"
            except Exception as e:
                ret = "error"
                msg += f"error data={data}"
                print(e)
                raise e

            ret = (json.dumps(ret) + "?END?").encode()
            try:
                conn.send(ret)
            except Exception as e:
                msg += f" error sending result: {ret}"
                print(e)
            print(msg)
        s.close()

def main(args):
    try:
        root = args[1]
        mount = args[2]
    except IndexError:
        print("ERROR: two arguments required, <root> and <mount>")
        return
    for d in [root, mount]:
        if not os.path.isdir(d):
            print(f"ERROR: '{d}' is not a directory")
            return
    if len(os.listdir(mount)) != 0:
        print(f"ERROR: '{mount}' is not empty")
        return

    username = input("Enter username: ")
    password = input("Enter password: ")

    aw = FSAccessWrapper()
    su = SharingUtility(username, password, access_wrapper=aw)
    fs = ShareFS(args[1], args[2], su)
    aw.fs = fs
    threading.Thread(target=fs.start_server).start()
    fs.start()
