import os
import fcntl
import socket
import select
import logging
import threading
import time
import struct
import ctypes
import dbus
import dbus.service
import dbus.mainloop.glib
import gi.repository.GLib
logger = logging.getLogger(__name__)

class BtMouse():
    UUID = '00001124-0000-1000-8000-00805f9b34fb'
    PSM_CTRL = 0x11
    PSM_INTR = 0x13
    SOL_BLUETOOTH = 274
    BT_POWER = 9

    class BluezAgent(dbus.service.Object, threading.Thread):
        def __init__(self, path, uuid):
            self.UUID = uuid
            self.mainloop = gi.repository.GLib.MainLoop()
            dbus.service.Object.__init__(self, dbus.SystemBus(mainloop=dbus.mainloop.glib.DBusGMainLoop()), path)
            threading.Thread.__init__(self)

        def run(self):
            self.mainloop.run()

        def stop(self):
            self.mainloop.quit()

        def register(self):
            agent_manager = dbus.Interface(self._connection.get_object('org.bluez', '/org/bluez'), 'org.bluez.AgentManager1')
            agent_manager.RegisterAgent(self._object_path, 'NoInputNoOutput')
            agent_manager.RequestDefaultAgent(self._object_path)

        @dbus.service.method('org.bluez.Agent1', in_signature='o', out_signature='')
        def RequestAuthorization(self, device):
            logger.info('RequestAuthorization (%s)' % (device))
            return

        @dbus.service.method('org.bluez.Agent1', in_signature='os', out_signature='')
        def AuthorizeService(self, device, uuid):
            if uuid != self.UUID:
                logger.info('Rejecting non-HID Service: %s' % (uuid))
                raise dbus.DBusException(name='org.bluez.Error.Rejected')

            logger.info('Authorized HID Service: %s' % (uuid))
            return

    def __init__(self, bdaddr, alias, sdp_record):
        self.alias = alias
        logger.info('Initializing {}'.format(self.alias))
        self.bdaddr = bdaddr
        self.sdp_record = sdp_record
        self.hci_index = None
        self.hci_adapter_path = None
        self.lsock_control = None
        self.sock_control = None
        self.lsock_interrupt = None
        self.sock_interrupt = None
        self.sock_hci = None
        self.connection_handle = None
        self.paired_bdaddr = None
        self.agent = None
        self.paired = False
        self.host_connected = False
        self.hid_handshake = False
        self.sniff_mode = False
        self.poller = select.poll()
        self.btpow = struct.pack('B', 0)

    def connect(self, paired_bdaddr = None):
        if paired_bdaddr:
            self.paired = True
            self.paired_bdaddr = paired_bdaddr
            self.paired_mode_connect()
        else:
            self.pairing_mode_connect()

    def pairing_mode_connect(self):
        self.agent = self.BluezAgent('/robomouse/agent', self.UUID)
        self.agent.register()
        self.agent.start()
        self.bus = dbus.SystemBus()
        self.config_hci_adapter()
        self.config_sdp_record()
        self.listen_host()
        self.agent.stop()
        self.wait_for_hid_handshake()
        time.sleep(1.2) #wait for the dust to settle
        self.connection_handle = self.get_connection_handle()

    def paired_mode_connect(self):
        self.bus = dbus.SystemBus()
        self.config_hci_adapter()
        self.reconnect_host()
        self.wait_for_hid_handshake()
        self.connection_handle = self.get_connection_handle()

    def config_hci_adapter(self):
        self.hci_adapter_path = self.get_adapter_path(self.bdaddr)
        self.hci_index = int(self.hci_adapter_path[-1:])
        self.set_cod()
        self.adapter_obj = self.bus.get_object('org.bluez', self.hci_adapter_path)
        self.adapter_iface = dbus.Interface(self.adapter_obj, 'org.bluez.Adapter1')
        self.adapter_props = dbus.Interface(self.adapter_obj, 'org.freedesktop.DBus.Properties')
        self.adapter_props.Set('org.bluez.Adapter1', 'Alias', self.alias)
        self.adapter_props.Set('org.bluez.Adapter1', 'Discoverable', True)
        self.adapter_props.Set('org.bluez.Adapter1', 'DiscoverableTimeout', dbus.UInt32(0))

    def get_adapter_path(self, bdaddr):
        manager = dbus.Interface(self.bus.get_object('org.bluez', '/'),'org.freedesktop.DBus.ObjectManager')

        for path, obj in manager.GetManagedObjects().items():
            adapter_props = obj.get('org.bluez.Adapter1')
            if adapter_props and adapter_props['Address'] == bdaddr:
                return path

    def wait_for_hid_handshake(self):
        count = 0
        while not self.hid_handshake and count < 500:
            self.poll_sockets()
            count += 1
            time.sleep(.001)

    def get_management_socket(self):
        HCI_DEVICE_NONE = 0xffff
        HCI_USER_CHANNEL = 3

        class sockaddr_hci(ctypes.Structure):
            _fields_ = [("sin_family", ctypes.c_ushort),
                        ("hci_dev", ctypes.c_ushort),
                        ("hci_channel", ctypes.c_ushort)]

        libc = ctypes.cdll.LoadLibrary("libc.so.6")
        libc.socket.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_int)
        libc.bind.argtypes = (ctypes.c_int, ctypes.POINTER(sockaddr_hci), ctypes.c_int)

        addr = sockaddr_hci(socket.AF_BLUETOOTH, HCI_DEVICE_NONE, HCI_USER_CHANNEL)
        mgmt_sock_fd = libc.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
        libc.bind(mgmt_sock_fd, ctypes.POINTER(sockaddr_hci)(addr), ctypes.sizeof(sockaddr_hci))

        return mgmt_sock_fd

    def set_cod(self):
        mgmt_sock_fd = self.get_management_socket()
        cod_cmd = struct.pack('3H2B', 0x000E, self.hci_index, 2, 5, 128)
        os.write(mgmt_sock_fd, cod_cmd)
        os.close(mgmt_sock_fd)

    def get_connection_handle(self):
        ACL_LINK = 1
        HCIGETCONNINFO = 2147764437

        self.sock_hci = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
        self.sock_hci.bind((self.hci_index,))

        bdaddr_bytes = bytearray.fromhex(self.paired_bdaddr.replace(':', ''))[::-1]
        args = bytearray(struct.pack('6sB17s', bdaddr_bytes, ACL_LINK, bytes(0x00) * 17))
        fcntl.ioctl(self.sock_hci, HCIGETCONNINFO, args, 1)
        handle = struct.unpack('8xH14x', args)[0]

        return handle

    def enter_sniff(self):
        ogf_ocf = (0x02 << 10 | 0x0003).to_bytes(2, byteorder='little')
        cmd = struct.pack('B2sB5H', 0x01, ogf_ocf, 0x0a, self.connection_handle, 0x0012, 0x0012, 0x0009, 0x0009)
        self.sock_hci.send(cmd)
        self.sniff_mode = True

    def exit_sniff(self):
        ogf_ocf = (0x02 << 10 | 0x0004).to_bytes(2, byteorder='little')
        cmd = struct.pack('B2sBH', 0x01, ogf_ocf, 0x02, self.connection_handle)
        self.sock_hci.send(cmd)
        self.sniff_mode = False

    def config_sdp_record(self):
        logger.info('Configuring bluez profile')

        sdp_opts = {'Role': 'server',
                    'RequireAuthentication': False,
                    'RequireAuthorization': False,
                    'AutoConnect': True,
                    'ServiceRecord': self.sdp_record}

        profile_manager = dbus.Interface(self.bus.get_object('org.bluez', '/org/bluez'), 'org.bluez.ProfileManager1')
        profile_manager.RegisterProfile('/bluez/robomouse/robomouse_profile', self.UUID, sdp_opts)
        logger.info('Profile registered')

    def close(self):
        self.close_sockets()

        if self.agent:
            self.agent.stop()

    def close_sockets(self):
        if self.sock_hci:
            self.sock_hci.close()
            self.sock_hci = None

        if self.sock_interrupt:
            try:
                self.poller.unregister(self.sock_interrupt.fileno())
            except:
                pass
            self.sock_interrupt.close()
            self.sock_interrupt = None
        if self.sock_control:
            try:
                self.poller.unregister(self.sock_control.fileno())
            except:
                pass
            self.sock_control.close()
            self.sock_control = None

        self.host_connected = False
        self.hid_handshake = False
        self.sniff_mode = False

    def poll_sockets(self):
        if not self.host_connected:
            return

        poll_result = self.poller.poll(.001)

        if poll_result:
            for fd, event in poll_result:
                if (fd == self.sock_control.fileno()) or (fd == self.sock_interrupt.fileno()):
                    if event & select.POLLIN: #respond to HID handshake
                        try:
                            data = self.sock_control.recv(1024)
                            self.sock_control.send(bytes([0]))
                            self.hid_handshake = True
                        except:
                            logger.info('Handshake failed')
                            self.host_connected = False
                            raise ConnectionAbortedError()
                    if event & select.POLLERR:
                        logger.info('poll returned socket error')
                        raise ConnectionResetError()

    def listen_host(self):
        self.lsock_control = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
        self.lsock_control.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lsock_control.setsockopt(self.SOL_BLUETOOTH, self.BT_POWER, self.btpow)
        self.lsock_control.bind((self.bdaddr, self.PSM_CTRL))
        self.lsock_control.listen(1)

        self.lsock_interrupt = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
        self.lsock_interrupt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lsock_interrupt.setsockopt(self.SOL_BLUETOOTH, self.BT_POWER, self.btpow)
        self.lsock_interrupt.bind((self.bdaddr, self.PSM_INTR))
        self.lsock_interrupt.listen(1)
        logger.info('Waiting for connections')

        self.sock_control, cinfo = self.lsock_control.accept()
        logger.info('{} connected on the control socket'.format(cinfo[0]))
        self.lsock_control.close()

        self.sock_interrupt, cinfo = self.lsock_interrupt.accept()
        logger.info('{} connected on the interrupt socket'.format(cinfo[0]))
        self.lsock_interrupt.close()

        if self.sock_control:
            self.poller.register(self.sock_control.fileno(), select.POLLIN | select.POLLERR)
        if self.sock_interrupt:
            self.poller.register(self.sock_interrupt.fileno(), select.POLLERR)

        self.host_connected = True
        self.paired_bdaddr = cinfo[0]

    def reconnect_host(self):
        logger.info('Attempting reconnection to: {}'.format(self.paired_bdaddr))

        try:
            self.sock_control = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
            self.sock_control.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_control.setsockopt(self.SOL_BLUETOOTH, self.BT_POWER, self.btpow)
            self.sock_control.bind((self.bdaddr, 0))
            self.sock_control.connect((self.paired_bdaddr, self.PSM_CTRL))
            logger.info('{} connected on the control socket'.format(self.paired_bdaddr))
        except Exception as e:
            logger.info(e)
            self.close_sockets()
            raise ConnectionRefusedError()

        try:
            self.sock_interrupt = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
            self.sock_interrupt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_interrupt.setsockopt(self.SOL_BLUETOOTH, self.BT_POWER, self.btpow)
            self.sock_interrupt.bind((self.bdaddr, 0))
            self.sock_interrupt.connect((self.paired_bdaddr, self.PSM_INTR))
            logger.info('{} connected on the interrupt socket'.format(self.paired_bdaddr))
        except Exception as e:
            logger.info(e)
            self.close_sockets()
            raise ConnectionRefusedError()

        if self.sock_control:
            self.poller.register(self.sock_control.fileno(), select.POLLIN | select.POLLERR)
        if self.sock_interrupt:
            self.poller.register(self.sock_interrupt.fileno(), select.POLLERR)

        self.host_connected = True

    def send(self, msg):
        self.sock_interrupt.send(bytes(bytearray(msg)))
