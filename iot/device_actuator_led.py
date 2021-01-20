"""An LED actuator. Uses PWM for the selected pin"""

from iot.device import IoTDevice
import RPi.GPIO as GPIO

class LED(IoTDevice):
    def __init__(self):
        super().__init__(device_passphrase = "123",
                         device_type       = "actuator",
                         device_id         = "led-1",
                         update_period     = 5,
                         pin               = 21)

    def init(self):
        super().init()
        # initializing the gpio pin
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(self.pin, GPIO.OUT)
        self.pwm = GPIO.PWM(self.pin, 100)
        self.pwm.start(0)

    def finalize(self):
        self.pwm.stop()
        GPIO.cleanup()

    def file_name(self):
        return self.first_shared_file_name()

    def write_actuator(self, values):
        value = values[-1]
        value = int(value.decode())
        if value > 100:
            self.warning(f"input value larger than 100 ({value})")
            value = 100
        elif value < 0:
            self.warning(f"input value less than 0 ({value})")
            value = 0
        try:
            self.pwm.ChangeDutyCycle(value)
        except Exception as e:
            self.error(f"failed setting cycle ({e})")

def main(args):
    LED().run()
