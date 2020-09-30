"""An example sensor that writes random integers from 0 to 255"""

from device import IoTDevice
import random

class FakeSensor(IoTDevice):
    def __init__(self):
        super().__init__(server_ip         = "127.0.0.1",
                         server_port       = 2010,
                         device_passphrase = "123",
                         device_type       = "sensor",
                         device_id         = "alice-sens",
                         update_period     = 1.5,
                         log_count         = 5) # TODO

    def file_name(self):
        return self.device_id + ".file"

    def shared_with_list(self):
        return ["bob-act"]

    def read_sensor(self):
        return random.randint(0, 255)

FakeSensor().run()
