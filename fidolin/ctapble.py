import asyncio, enum, logging

from fidolin.fidotoken import FidoToken
from fidolin.ctap import CTAP_Capability, CTAP_Command, CTAP_Frame, \
    CTAP_InitializationFrame, CTAP_ContinuationFrame , CTAP_ErrorFrame, \
    CTAP_InitRequestFrame, CTAP_InitResponseFrame, CTAP_MsgRequestFrame, \
    CTAP_MsgResponseFrame, CTAP_PingFrame, CTAP_WinkFrame

# in contrast to the USB HID frames the BLE frames do not contain a channel id
# and their size may differ from the default 64 bytes for USB. The FeiTian Multipass
# aka Titan Bluetooth Token has a frame size of 20 bytes 

CTAPBLE_RequestFrameClasses = [
    CTAP_PingFrame,
    CTAP_InitRequestFrame,
    CTAP_WinkFrame,
    CTAP_MsgRequestFrame,
]
CTAPBLE_RequestFrameClassByCommandId = \
    dict((p._command_id, p) for p in CTAPBLE_RequestFrameClasses)
CTAPBLE_ResponseFrameClasses = [
    CTAP_PingFrame,
    CTAP_InitResponseFrame,
    CTAP_WinkFrame,
    CTAP_ErrorFrame,
    CTAP_MsgResponseFrame,
]
CTAPBLE_ResponseFrameClassByCommandId = \
    dict((p._command_id, p) for p in CTAPBLE_ResponseFrameClasses)

