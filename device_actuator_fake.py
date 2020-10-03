"""An example fake actuator that prints the input value to stdout"""

from device import IoTDevice

class FakeActuator(IoTDevice):
    def __init__(self):
        super().__init__(device_passphrase = "abc",
                         device_type       = "actuator",
                         device_id         = "bob-act",
                         update_period     = 3)

    def file_name(self):
        return self.first_shared_file_name()

    def write_actuator(self, values):
        self.log(f"FAKE ACTUATOR WRITE ({values})")

FakeActuator().run()
