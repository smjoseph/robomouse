import os
import select
import evdev
import logging
import time
logger = logging.getLogger(__name__)

class EvdevMouse():
    def __init__(self, dev_path, reverse_scroll):
        self.dev_path = dev_path
        self.reverse_scroll = reverse_scroll
        self.mouse = None
        self.poller = select.poll()
        self.hid_report = [161, 13, 0, 0, 0, 0]

    def get_mouse(self):
        if not self.mouse:
            logger.info('Acquiring mouse')
            while True:
                if os.path.exists(self.dev_path):
                    self.mouse = evdev.InputDevice(self.dev_path)
                    self.ui = evdev.UInput.from_device(self.mouse)
                    break
                time.sleep(.001)

            self.poller.register(self.mouse.fileno(), select.POLLIN | select.POLLERR)
            self.mouse.grab()
            logger.info('Mouse found')

    def close_mouse(self):
        if self.mouse:
            self.mouse.close()
            self.mouse = None

    def poll_mouse(self):
        evdev_events = []
        poll_result = self.poller.poll(.001)

        if poll_result:
            for fd, event in poll_result:
                if fd == self.mouse.fileno():
                    if event & select.POLLIN:
                        try:
                            evdev_events = self.mouse.read()
                        except OSError as osError:
                            logger.info('failed to read mouse device')
                            raise osError
                    elif event & select.POLLERR:
                        logger.info('poll returned mouse error')
                        raise RuntimeError()

        return evdev_events

    def create_hid_report(self, events):
        if not events:
            return

        self.hid_report[3:] = [0, 0, 0]

        for event in events:
            if event.type == 2:
                if event.value < 0:
                    event.value = 0x0100 + event.value
                if event.code == 0:
                    self.hid_report[3] = event.value
                elif event.code == 1:
                    self.hid_report[4] = event.value
                elif event.code == 8:
                    if self.reverse_scroll:
                        event.value = -event.value & 0xFF
                    self.hid_report[5] = event.value
            elif event.type == 1:
                if event.code == 272:
                    if event.value == 0:
                        self.hid_report[2] &= 0xFE  # unset bit 1
                    elif event.value == 1:
                        self.hid_report[2] |= 0x01  # set bit 1
                elif event.code == 273:
                    if event.value == 0:
                        self.hid_report[2] &= 0xFD  # unset bit 2
                    elif event.value == 1:
                        self.hid_report[2] |= 0x02  # set bit 2
                elif event.code == 274:
                    if event.value == 0:
                        self.hid_report[2] &= 0xFB  # unset bit 3
                    elif event.value == 1:
                        self.hid_report[2] |= 0x04  # set bit 3

        return self.hid_report
