"""TCP server"""

import socket
import datetime
import os

PORT = os.getenv("PORT") or 2010
PORT = int(PORT)

class FSInterface:
    def get(self, path: str):
        raise Exception("Not implemented")

    def set(self, path: str, data: bytes):
        raise Exception("Not implemented")

    def rm(self, path: str):
        raise Exception("Not implemented")

    def ls(self):
        raise Exception("Not implemented")

    def exists(self, path: str):
        raise Exception("Not implemented")

    def preview(self):
        print("FS TREE:")
        for f in self.ls():
            print(f"> {f}:")
            print(self.get(f))
            print("")

class DiskFS(FSInterface):
    def __init__(self):
        self.root = "./diskfs/"

    def get(self, path: str):
        f = open(self.root + path, "rb")
        res = f.read()
        f.close()
        return res

    def set(self, path: str, data: bytes):
        f = open(self.root + path, "wb")
        f.write(data)
        f.close()

    def rm(self, path: str):
        os.remove(self.root + path)

    def ls(self):
        return os.listdir(self.root)

    def exists(self, path: str):
        return os.path.exists(self.root + path)

class MemoryFS(FSInterface):
    def __init__(self):
        self.fs = {}

    def get(self, path: str):
        return self.fs[path]

    def set(self, path: str, data: bytes):
        self.fs[path] = data

    def rm(self, path: str):
        del self.fs[path]

    def ls(self):
        return self.fs.keys()

    def exists(self, path: str):
        return path in self.fs

def date():
    return str(datetime.datetime.now())

def start_server(port, fs):
    BUFFER_SIZE = 1024
    running = True
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', port))
    s.listen(1)
    print(f"{date()}: Server started at :{port}")
    while running:
        conn, addr = s.accept()
        print(f"{date()}: Connection address: {addr}")
        
        # recieving data
        data = b""
        while True:
            tmp = conn.recv(BUFFER_SIZE)
            data += tmp
            if not tmp or data.endswith(b"?END?"): break

        print(f"{date()}: Recieved: {data}")
        
        # process
        data = data.split(b"?")
        cmd = data[0]
        if len(data) >= 2:
            # to make files ip-dependant
            # path = f"{addr[0]}_{data[1].decode()}"
            path = data[1].decode()
        else:
            path = None
        if cmd == b"DIE":
            running = False
            s.close()
            conn.send(b"t") # ack
            conn.close()
        elif cmd == b"SET":
            try:
                del data[0:2] # remove cmd and path
                del data[-1]  # remove the b"?END?"
                del data[-1]
                data = b"?".join(data) # fixes if data has "?"
                fs.set(path, data)
                conn.send(b"t") # ack
                conn.close()
            except:
                conn.send(b"f") # ack
                conn.close()
        elif cmd == b"GET":
            try:
                conn.send(fs.get(path))
                conn.close()
            except Exception as e:
                conn.send(b"f") # ack
                conn.close()
                print(f"{date()}: Error sending")
                print(e)
        elif cmd == b"RM":
            try:
                fs.rm(path)
                conn.send(b"t") # ack
                conn.close()
            except:
                conn.send(b"f") # ack
                conn.close()
        elif cmd == b"IN":
            try:
                conn.send(b"1" if fs.exists(path) else b"0")
                conn.close()
            except Exception as e:
                conn.send(b"f") # ack
                conn.close()
                print(f"{date()}: Error sending")
                print(e)
        else:
            print(f"{date()}: Unknown command '{cmd}'")

        fs.preview()

def main(args):
    if args[1] == "--volatile":
        start_server(PORT, MemoryFS())
    else:
        start_server(PORT, DiskFS())
