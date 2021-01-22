import os

from core.sharing import SharingUtility
from fs.crypto_fs import CryptoFS, fuse_mount

class ShareFS(CryptoFS):

    def __init__(self, root, mount, sharing_util):
        super().__init__(root, mount)
        self.su = sharing_util
        os.makedirs(f"{self.root}/{self.su.user_id}", exist_ok=True)

    def key_gen(self, iv):
        # return self.su.keys["sym"]
        return self.su.key_gen(iv)

    def translate_path(self, path):
        return self.root + "/" + self.su.user_id + path

    def lsdir(self, path):
        real_path = self.translate_path(path)
        ls = os.listdir(real_path)
        if path == "/":
            ls.append("shared")
        return ls

# TODO: create AcessWrapper
# TODO: create commands operations (i.e. share, revoke)

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
    su = SharingUtility(username, password)
    fs = ShareFS(args[1], args[2], su)
    fuse_mount(fs, f"sharefs:{su.user_id}")
