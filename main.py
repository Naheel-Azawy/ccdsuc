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
    "bcpki": Command("control BlockChain Public Key Infrastructure",
                     "public_key.pki_bc"),
    "fs-mount": Command("mount sharing filesystem <root> to <mount>",
                        "fs.sharing_fs"),
    "fs-cmd": Command("execute a command on a mounted fs",
                        "fs.sharing_fs_client"),
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
    "test": Command("run the test functions",
                    "testing.test"),
    "test2": Command("run the test functions",
                     "testing.test2")
}

def usage():
    print("usage: thething COMMAND [ARGS]")
    print("COMMANDS:")
    for cmd in commands:
        if cmd != "test":
            print("  %-15s %s" % (cmd, commands[cmd].det))

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
