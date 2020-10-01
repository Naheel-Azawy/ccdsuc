"""TCP server interface from the client"""

import socket
import time

class Server:

    def __init__(self, ip, port, device=None):
        self.addr = (ip, port)
        self.device = device
        self.fail_period = 10

    def err(self, msg):
        if self.device is not None:
            self.device.error(msg)
        else:
            print(f"ERROR: {msg}")

    def connect(self):
        again = True
        while again:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(self.addr)
                again = False
                return s
            except ConnectionRefusedError:
                self.err("server connection refused. " +
                         f"Retrying in {self.fail_period} seconds...")
                time.sleep(self.fail_period)
        return None # unreachable

    def set(self, path: str, data: bytes):
        s = self.connect()
        # request
        req = ("SET?" + path + "?").encode() + data + b'?END?'
        s.send(req)
        # acknowledge
        ack = s.recv(10)
        s.close()
        return ack == b"t"

    def get(self, path: str):
        s = self.connect()
        # request
        req = ("GET?" + path + "?END?").encode()
        s.send(req)
        # recieve data
        data = b""
        while 1:
            tmp = s.recv(1024)
            data += tmp
            if not tmp: break
        s.close()
        return data if data != b"f" else None

    def kill(self):
        s = self.connect()
        # request
        req = b"DIE?END?"
        s.send(req)
        # acknowledge
        ack = s.recv(10)
        s.close()
        return ack == b"t"

    def rm(self, path: str):
        s = self.connect()
        # request
        req = ("RM?" + path + "?END?").encode()
        s.send(req)
        # acknowledge
        ack = s.recv(10)
        s.close()
        return ack == b"t"

    def exists(self, path: str):
        s = self.connect()
        # request
        req = ("IN?" + path + "?END?").encode()
        s.send(req)
        # acknowledge
        ack = s.recv(10)
        s.close()
        return ack == b"1"

    def example():
        s = Server("127.0.0.1", 8080)
        #print(s.set("foo.txt", b"123 abc"))
        #print(s.get("foo.txt"))
        #print(s.exists("foo.txt"))
        #print(s.rm("foo.txt"))
        #print(s.kill())
