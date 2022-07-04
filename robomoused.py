#!/usr/bin/python3 -B
import sys
sys.path.append('/usr/local/lib')
import os
import signal
import logging
import systemd.journal
import multiprocessing
import argparse
import time
import random
import re
import queue
import ctypes
import robomouse.evdev.evdevmouse
import robomouse.bt.btmouse
logger = logging.getLogger(__name__)

class RoboMouse():
    FOCUS_LOCAL = 0
    FOCUS_HOST = 1
    SDP_RECORD = '<?xml version=\"1.0\" encoding=\"UTF-8\"?><record><attribute id=\"0x0001\"><sequence><uuid value=\"0x1124\"/></sequence></attribute><attribute id=\"0x0004\"><sequence><sequence><uuid value=\"0x0100\"/><uint16 value=\"0x0011\"/></sequence><sequence><uuid value=\"0x0011\"/></sequence></sequence></attribute><attribute id=\"0x0005\"><sequence><uuid value=\"0x1002\"/></sequence></attribute><attribute id=\"0x0006\"><sequence><uint16 value=\"0x656e\"/><uint16 value=\"0x006a\"/><uint16 value=\"0x0100\"/></sequence></attribute><attribute id=\"0x0009\"><sequence><sequence><uuid value=\"0x1124\"/><uint16 value=\"0x0100\"/></sequence></sequence></attribute><attribute id=\"0x000d\"><sequence><sequence><sequence><uuid value=\"0x0100\"/><uint16 value=\"0x0013\"/></sequence><sequence><uuid value=\"0x0011\"/></sequence></sequence></sequence></attribute><attribute id=\"0x0100\"><text value=\"ROBOMOUSE\"/></attribute><attribute id=\"0x0101\"><text value=\"ROBOMOUSE\"/></attribute><attribute id=\"0x0102\"><text value=\"ROBOMOUSE\"/></attribute><attribute id=\"0x0201\"><uint16 value=\"0x0111\"/></attribute><attribute id=\"0x0202\"><uint8 value=\"0x80\"/></attribute><attribute id=\"0x0203\"><uint8 value=\"0x00\"/></attribute><attribute id=\"0x0204\"><boolean value=\"true\"/></attribute><attribute id=\"0x0205\"><boolean value=\"true\"/></attribute><attribute id=\"0x0206\"><sequence><sequence><uint8 value=\"0x22\"/><text encoding=\"hex\" value=\"05010902A101850D0901A100050919012903150025017501950881020501093009311581257F75089502810609381581257f750895018106C0C0\"/></sequence></sequence></attribute><attribute id=\"0x0207\"><sequence><sequence><uint16 value=\"0x0409\"/><uint16 value=\"0x0100\"/></sequence></sequence></attribute><attribute id=\"0x020a\"><boolean value=\"true\"/></attribute><attribute id=\"0x020c\"><uint16 value=\"0x0c80\"/></attribute><attribute id=\"0x020d\"><boolean value=\"false\"/></attribute><attribute id=\"0x020e\"><boolean value=\"true\"/></attribute><attribute id=\"0x020f\"><uint16 value=\"0x12\"/></attribute><attribute id=\"0x0210\"><uint16 value=\"0x0\"/></attribute></record>'

    def __init__(self, args):
        self.trigger_button = args.trigger_button
        self.jiggle_interval = args.jiggle_interval
        self.jiggle = args.jiggle
        self.reverse_scroll = args.reverse_scroll
        self.evdev_path = args.evdev_path
        self.pairing_mode = args.pairing_mode
        self.evdevmouse = robomouse.evdev.evdevmouse.EvdevMouse(self.evdev_path, self.reverse_scroll)
        self.btmouse = robomouse.bt.btmouse.BtMouse(args.bdaddr, 'ROBOMOUSE', self.SDP_RECORD)
        self.hid_queue = multiprocessing.Queue()
        self.focus = multiprocessing.Value(ctypes.c_int, self.FOCUS_LOCAL)
        self.trigger_pressed = multiprocessing.Value(ctypes.c_bool, False)
        self.mouse_connected = multiprocessing.Value(ctypes.c_bool, False)
        self.next_jiggle = 0
        self.evdevmouse_process = multiprocessing.Process(target=self.evdevmouse_core_loop)
        if args.dedicated_adapter:
            self.btmouse_process = multiprocessing.Process(target=self.dedicated_btmouse_core_loop)
        else:
            self.btmouse_process = multiprocessing.Process(target=self.btmouse_core_loop)

    def launch(self):
        self.evdevmouse_process.start()
        self.btmouse_process.start()
        self.evdevmouse_process.join()
        self.btmouse_process.join()

    def close(self):
        self.hid_queue.close()
        self.btmouse.close()
        self.evdevmouse.close_mouse()

    def send_jiggle(self):
        rand = random.randint(0, 3)
        jiggle_report = [161, 13, 0, 0, 0, 0]
        jiggle_report[3 + (rand >> 1)] = ((0xFE) * (rand & 0x1)) + ((~rand) & 0x1)

        try:
            self.btmouse.send(jiggle_report)
            logger.info('Jiggle sent: {}'.format(jiggle_report))
        except Exception as e:
            logger.info('Jiggle failed')
            logger.info(e)

        self.next_jiggle = self.jiggle_interval + time.perf_counter() + rand

    def store_paired_host_address(self, paired_bdaddr):
        os.makedirs('/var/lib/robomouse', 0o755, True)
        flat_file = open('/var/lib/robomouse/paired_bdaddr', 'w')
        flat_file.write(paired_bdaddr)
        flat_file.close()

    def retrieve_paired_host_address(self):
        bdaddr_pattern = r'[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}'

        try:
            flat_file = open('/var/lib/robomouse/paired_bdaddr', 'r')
            line = flat_file.readline(17)
            flat_file.close()

            if re.match(bdaddr_pattern, line):
                return line
            else:
                return None
        except Exception as e:
            logger.info(e)

    def set_trigger_pressed(self):
        self.trigger_pressed.value = True

    def check_trigger_pressed(self):
        trigger_pressed = self.trigger_pressed.value
        self.trigger_pressed.value = False

        return trigger_pressed

    def increment_focus(self):
        self.focus.value = not self.focus.value

    def handle_sniff(self):
        if self.focus.value == self.FOCUS_HOST:
            self.btmouse.exit_sniff() #reset in case host decided to enter sniff
            self.btmouse.enter_sniff()
        else:
            self.btmouse.exit_sniff()

    def evdevmouse_core_loop(self):
        self.evdevmouse.get_mouse()
        self.mouse_connected.value = True
        report_events = []

        while True:
            try:
                evdev_events = self.evdevmouse.poll_mouse()
            except Exception:
                self.mouse_connected.value = False
                self.evdevmouse.close_mouse()
                self.evdevmouse.get_mouse()
                self.mouse_connected.value = True

            for event in evdev_events:
                if event.code != self.trigger_button:
                    if self.focus.value == self.FOCUS_LOCAL:
                        self.evdevmouse.ui.write_event(event)
                    elif event.type == 0:
                        if report_events:
                            self.hid_queue.put_nowait(self.evdevmouse.create_hid_report(report_events))
                            report_events.clear()
                    elif event.type in [1, 2]:
                        report_events.append(event)
                else:
                    if event.value == 0:
                        self.set_trigger_pressed()

    def btmouse_core_loop(self):
        self.btmouse.connect(paired_bdaddr = None if self.pairing_mode else self.retrieve_paired_host_address())

        if self.btmouse.host_connected:
            logger.info('Bluetooth connection established')
            self.store_paired_host_address(self.btmouse.paired_bdaddr)

        while True:
            try:
                self.btmouse.poll_sockets()
                self.btmouse.send(self.hid_queue.get_nowait())
            except ConnectionError:
                self.focus.value = self.FOCUS_LOCAL
                self.btmouse.close_sockets()
            except queue.Empty:
                pass

            if self.check_trigger_pressed():
                if self.btmouse.host_connected:
                    self.increment_focus()
                    self.handle_sniff()
                else:
                    self.btmouse.paired_mode_connect()
                    self.focus.value = self.FOCUS_HOST
                    self.handle_sniff()

            if not self.mouse_connected.value:
                self.focus.value = self.FOCUS_LOCAL
                if self.btmouse.host_connected:
                    self.handle_sniff()

            if self.jiggle and self.btmouse.host_connected:
                if time.perf_counter() >= self.next_jiggle:
                    self.send_jiggle()

            time.sleep(.001)

    def dedicated_btmouse_core_loop(self):
        self.btmouse.connect(paired_bdaddr = None if self.pairing_mode else self.retrieve_paired_host_address())

        if self.btmouse.host_connected:
            logger.info('Bluetooth connection established')
            self.btmouse.enter_sniff()
            self.store_paired_host_address(self.btmouse.paired_bdaddr)

        while True:
            try:
                self.btmouse.poll_sockets()
                self.btmouse.send(self.hid_queue.get_nowait())
            except ConnectionError:
                self.focus.value = self.FOCUS_LOCAL
                self.btmouse.close_sockets()
            except queue.Empty:
                pass

            if self.check_trigger_pressed():
                if self.btmouse.host_connected:
                    self.increment_focus()
                else:
                    self.btmouse.paired_mode_connect()
                    self.btmouse.enter_sniff()
                    self.focus.value = self.FOCUS_HOST

            if not self.mouse_connected.value:
                    self.focus.value = self.FOCUS_LOCAL

            if self.jiggle:
                if time.perf_counter() >= self.next_jiggle:
                    self.send_jiggle()

            time.sleep(.001)

def SignalSetup():
    signal.signal(signal.SIGTERM, SignalHandler)
    signal.signal(signal.SIGINT, SignalHandler)

def SignalHandler(sig, frame):
    robomouse.close()
    sys.exit(0)

def SetupLogger():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('[%(levelname)s] %(message)s')

    if args.enable_syslog:
        syslog_handler = systemd.journal.JournalHandler(SYSLOG_IDENTIFIER='robomouse')
        syslog_handler.setFormatter(formatter)
        logger.addHandler(syslog_handler)
    else:
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setFormatter(formatter)
        logger.addHandler(stdout_handler)

    return logger

def ParseArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', action='store_true', default=False, dest='pairing_mode')
    parser.add_argument('-d', action='store_true', default=False, dest='dedicated_adapter')
    parser.add_argument('-m', action='store', default='/dev/input/bt-mouse', dest='evdev_path', type=str)
    parser.add_argument('-b', action='store', default=None, dest='bdaddr', type=str)
    parser.add_argument('-j', dest='jiggle_interval', const=290, default=None, action='store', nargs='?', type=int)
    parser.add_argument('-t', dest='trigger_button', const=None, default=276, action='store', nargs='?', type=int)
    parser.add_argument('-l', action='store_true', default=False, dest='enable_syslog')
    parser.add_argument('-rs', action='store_true', default=False, dest='reverse_scroll')
    args = parser.parse_args()
    args.jiggle = args.jiggle_interval is not None

    return args

if __name__ == '__main__':
    SignalSetup()
    args = ParseArgs()
    logger = SetupLogger()

    try:
        robomouse = RoboMouse(args)
        robomouse.launch()
    except SystemExit:
        pass
    except:
        e = sys.exc_info()
        logger.error(e)
