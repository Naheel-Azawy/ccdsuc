import socket

def usage():
    print("Allowed commands:")
    print("<PORT> share     <FILE_PATH> <USER>")
    print("<PORT> revoke    <FILE_PATH> <USER>")
    print("<PORT> ls-shares <FILE_PATH>")

def main(args):
    args = args[1:]
    if len(args) not in [3, 4]:
        usage()
        return
    port      = int(args[0])
    cmd       = args[1]
    file_path = args[2]
    bob       = args[3] if len(args) == 4 else None
    if cmd not in ["share", "revoke", "ls-shares"]:
        usage()
        return

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("localhost", port))
    s.send(f"{cmd} {bob} {file_path}?END?".encode())
    BUFFER_SIZE = 1024
    data = b""
    while True:
        tmp = s.recv(BUFFER_SIZE)
        data += tmp
        if not tmp or data.endswith(b"?END?"): break
    data = data.decode().replace("?END?", "")
    print(data)
    s.close()
