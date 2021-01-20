#!/usr/bin/env python3

import importlib
from sys import argv

class Command:
    def __init__(self, det, fun):
        self.det = det
        self.fun = fun

def ls_commands(args):
    for c in commands:
        print(c)

commands = {
    "commands": Command("list the below commands",
                        ls_commands),
    "iot-server": Command("start the sample TCP server",
                          "iot.tcp_server"),
    "iot-sens-fake": Command("fake sensor",
                             "iot.device_sensor_fake"),
    "iot-act-fake": Command("fake actuator",
                            "iot.device_actuator_fake"),
    "iot-sens-ldr": Command("LDR sensor with raspberry pi",
                            "iot.device_sensor_ldr"),
    "iot-act-led": Command("LED with raspberry pi",
                           "iot.device_actuator_led"),
    "bcpki": Command("control BlockChain Public Key Infrastructure",
                     "public_key.pki_bc"),
    "fs-mount": Command("mount sharing filesystem <root> to <mount>",
                        "fs.sharing_fs")
}

def usage():
    print("usage: thething COMMAND [ARGS]")
    print("COMMANDS:")
    for cmd in commands:
        print(f"  {cmd}\t{commands[cmd].det}")
        # if commands[cmd].args is not None:
        #     args = ", ".join(commands[cmd].args)
        #     print(f"  \tARGS: {args}")

def main():
    if len(argv) > 1 and argv[1] in commands:
        cmd = commands[argv[1]]
        args = argv[1:]
        if callable(cmd.fun):
            cmd.fun(args)
        else:
            try:
                m = importlib.import_module(cmd.fun)
                m.main(args)
            except ModuleNotFoundError as e:
                if e.name == "RPi":
                    print("ERROR: this commands only works on raspberry pi")
                elif e.name == "web3":
                    print("ERROR: this commands requires blockchain setup")
                else:
                    raise e
    else:
        usage()

if __name__ == "__main__":
    main()
