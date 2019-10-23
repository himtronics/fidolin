import asyncio, enum, logging

from fidolin.fidotoken import FidoToken
from fidolin.ctap import CTAP_Capability, CTAP_Command, CTAP_Frame, \
    CTAP_InitializationFrame, CTAP_ContinuationFrame

# in contrast to the USB HID frames the BLE frames do not contain a channel id
# and their size may differ from the default 64 bytes for USB. The FeiTian Multipass
# aka Titan Bluetooth Token has a frame size of 20 bytes 

class CTAPBLE_InitializationFrame(CTAP_InitializationFrame):
    pass

class CTAPBLE_PingFrame(CTAPBLE_InitializationFrame):
    _command_id = CTAP_Command.PING

class CTAPBLE_ContinuationFrame(CTAP_ContinuationFrame):
    pass
