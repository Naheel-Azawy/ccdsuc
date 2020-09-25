"""An example sensor that writes random integers from 0 to 255"""

from device import IoTDevice
import RPi.GPIO as GPIO
import time

class LDR(IoTDevice):
    def __init__(self):
        super().__init__(server_ip         = "127.0.0.1",
                         server_port       = 2010,
                         device_passphrase = "123",
                         device_type       = "sensor",
                         device_id         = "ldr-1",
                         update_period     = 2.5,
                         pin               = 17)

    def init(self):
        super().init()
        # initializing the gpio pin
        GPIO.setmode(GPIO.BCM)

    def finalize(self):
        GPIO.cleanup()

    def file_name(self):
        return self.device_id + ".file"

    def shared_with_list(self):
        return ["led-1"]

    def read_sensor(self):
        # define the darkest possible value
        darkest = 1000

        # output on the pin for
        GPIO.setup(self.pin, GPIO.OUT)
        GPIO.output(self.pin, GPIO.LOW)
        time.sleep(0.1)

        # change the pin back to input
        GPIO.setup(self.pin, GPIO.IN)

        # count until the pin goes high
        count = 0
        while (GPIO.input(self.pin) == GPIO.LOW and count <= darkest):
            count += 1

        # scale down to get in the range 0 to 100
        return count // 10

LDR().run()
