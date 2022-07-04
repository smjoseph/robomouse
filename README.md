## Robomouse
+ Emulates a bluetooth hid mouse. Relays input from an existing mouse device to a bluetooth host.

### Dependencies
+ A mouse device. Does not work with not trackpads, etc.
+ Python 3.8
+ Bluez >= 5.53
+ python3 evdev module: `apt-get install python3-evdev`
+ python3 dbus module: `apt-get install python3-dbus`
+ python3 systemd module: `apt-get install python3-systemd`

### System Configuration
+ Disable problematic Bluez plugins:
    + Bluez's input plugin must be disabled
        - Bluez input plugin is enabled by default and prevents binding any socket on PSMs needed for hid-input
        - Input plugin is needed to use bluetooth hid-input devices, so it's recommended to re-enable after pairing
        - Disable by editing /lib/systemd/system/bluetooth.service: `ExecStart=/usr/lib/bluetooth/bluetoothd --noplugin=input`
    + Recommended: Disable Bluez a2dp and avrcp plugins: `... --noplugin=a2dp,avrcp`
+ Recommended: evtest
    - Helpful for finding mouse devices and button information
    - Must be root to see mice
+ Recommended: create a udev rule to establish a consistent device path for your mouse

### Service Installation (Optional)
+ Copy robomouse.service to /etc/systemd/system/robomouse.service
+ Create /usr/local/bin/robomoused.py
+ Enable service with systemctl: `sudo systemctl enable robomouse`
+ Start service with systemctl: `sudo systemctl start robomouse`

### Usage
```
robomouse.py [-p] [-d] -m path -b bdaddr [-j interval] [-t button] [-rs ]
    **Must be run as root**
    -p              start robomouse in pairing-mode
    -d              dedicated adapter mode
    -m path         path to mouse input-device
    -b bdaddr       bdaddr of adapter that robomouse will use
    -j interval     enable jiggling to simulate periodic activity and optionally specify an interval.
    -l              enable logging to syslog instead of stdout
    -t button       specify button that will trigger switching focus between hosts
    -rs             reverse scroll direction
```
