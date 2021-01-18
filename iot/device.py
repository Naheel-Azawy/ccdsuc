"""The main interface to any IoT device"""

from pki              import FakePKI
#from pki_bc           import BCPKI
from tcp_client       import Server
from sharing_tcp      import TCPAccessWrapper
from sharing          import SharingUtility, gen_keys_from
from Crypto.PublicKey import RSA

import os
import time
import threading
import typing
import datetime

def date():
    return str(datetime.datetime.now())

class IoTDevice:
    """The main interface to any IoT device.
    Note that the server ip and port will be replaced if ADDR env variable
    is provideded."""
    def __init__(self, device_passphrase,
                 device_type, device_id, update_period,
                 server_ip="127.0.0.1", server_port=2010,
                 log_count=1, **kwargs):
        if device_type not in ["actuator", "sensor"]:
            raise Exception(f"Unknown device type '{device_type}'")

        self.device_type = device_type
        self.device_id = device_id

        env_addr = os.getenv("ADDR")
        if env_addr:
            env_addr = env_addr.split(":")
            self.server_ip = env_addr[0]
            self.server_port = int(env_addr[1])
        else:
            self.server_ip = server_ip
            self.server_port = server_port

        self.server = Server(self.server_ip, self.server_port, self)
        self.aw = TCPAccessWrapper(self.server)
        self.su = SharingUtility(device_id, device_passphrase,
                                 access_wrapper=self.aw,
                                 keys_cache=os.getenv("HOME") + f"/{device_id}")

        try:
            self.pki = BCPKI()
        except NameError:
            # if not imported, then we test with the fake one
            self.pki = FakePKI()

        self.period = update_period
        self.log_count = log_count
        self.running = False

        self.reading_file = None

        # setting extra attributes
        for a in kwargs:
            setattr(self, a, kwargs[a])

    def init(self):
        """Initialize the device"""
        self.info("initializing device...")
        self.info(f"server at {self.server_ip}:{self.server_port}")
        self.pki.init()
        if self.device_type == "actuator":
            return # actuators got nothing to share

        # if the file is not there, create a holder
        if not self.aw.file_exists(self.file_name()):
            self.aw.upload_file(self.su, self.file_name(), b"HOLDER")

        for bob in self.shared_with_list():
            if not self.su.is_shared(self.file_name(), bob):
                self.info(f"{self.file_name()} is not shared with {bob}. Sharing...")
                self.su.share_file(self.file_name(), bob,
                                   self.pki.get_key(bob))

    def run(self):
        """Initialize and start the device"""
        self.running = True
        self.init()
        while self.running:
            IoTDevice.TaskThread(self).start()
            time.sleep(self.period)
        self.info("stopping...")
        self.finalize()
        self.info("ENDED")

    class TaskThread(threading.Thread):
        """The device's running thread"""
        def __init__(self, device):
            threading.Thread.__init__(self)
            self.device = device

        def run(self):
            d = self.device
            f = d.file_name()
            if f is None:
                self.error("file_name is None")
                return
            if d.device_type == "sensor":
                reading = d.read_sensor()
                d.info(f"sending sensor reading {reading}")
                reading = str(reading).encode()     # encode to utf-8
                readings = d.aw.load_file(d.su, f)  # load the old file
                readings = readings.split(b'\n')
                readings.append(reading)            # add the new reading
                readings = readings[-d.log_count:]  # last N elements
                readings = b'\n'.join(readings)
                d.aw.upload_file(d.su, f, readings) # upload the new file
            elif d.device_type == "actuator":
                values = d.aw.load_file(d.su, f)
                values = values.split(b'\n')
                d.info(f"writing actuator value(s) {values}")
                d.write_actuator(values)
            else:
                raise Exception(f"Unknown device type {d.sevice_type}")

    def finalize(self):
        """Called once the device is stopped"""
        pass

    def kill(self):
        """Stop the device politely"""
        self.running = False

    def first_shared_file_name(self) -> str:
        """Utility method to get the first file shared with us"""
        if self.reading_file is None:
            files = self.su.list_files_shared_with_us(only_files=True)
            if files is None or len(files) == 0:
                self.error("No files shared with us")
                return None
            else:
                self.reading_file = files[0]
        return self.reading_file

    def log(self, msg):
        c = "\033[32m" if self.device_type == "sensor" else "\033[35m"
        print(f"{date()}: {c}[{self.device_id}]:\033[0m {msg}")

    def info(self, msg):
        self.log(f"\033[1m\033[34mINFO:\033[0m {msg}")

    def error(self, msg):
        self.log(f"\033[1m\033[31mERROR:\033[0m {msg}")

    def warning(self, msg):
        self.log(f"\033[1m\033[33mWARNING:\033[0m {msg}")

    def file_name(self) -> str:
        """Can be the file the device writes to if it's a sensor
        or the file the device reads to write it's value as an actuator"""
        raise Exception("Not implemented")

    def shared_with_list(self) -> typing.List[str]:
        """List of other device IDs we want to share data with (as a sensor)"""
        raise Exception("Not implemented")

    def read_sensor(self):
        """Get the sensor reading from the hardware"""
        raise Exception("Not implemented")

    def write_actuator(self, value):
        """Write a value to the actuator hardware"""
        raise Exception("Not implemented")
