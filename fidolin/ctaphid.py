import enum, os, time

from .ctap import CTAP_Frame, CTAP_Command, CTAP_InitializationFrame, \
    CTAP_ContinuationFrame, CTAP_InitRequestFrame, CTAP_InitResponseFrame, \
    CTAP_PingFrame, CTAP_WinkFrame, CTAP_ErrorFrame, \
    CTAP_MsgRequestFrame, CTAP_MsgResponseFrame

class CTAPHID_Frame(CTAP_Frame):
    def __init__(self, fido_token=None, *args):
        super().__init__(fido_token, *args)
        if fido_token:
            self.channel_id = fido_token.channel_id

    @property
    def channel_id(self):
        return int.from_bytes(self[0:4], byteorder='big')

    @channel_id.setter
    def channel_id(self, value):
        self[0:4] = value.to_bytes(4, byteorder='big')

CTAPHID_InitializationFrame = type('CTAP_InitializationFrame',
        (CTAPHID_Frame, CTAP_InitializationFrame), {})
CTAPHID_ContinuationFrame = type('CTAP_ContinuationFrame',
        (CTAPHID_Frame, CTAP_ContinuationFrame), {})
CTAPHID_ErrorFrame = type('CTAPHID_ErrorFrame', (CTAPHID_Frame, CTAP_ErrorFrame), {})
CTAPHID_InitRequestFrame = type('CTAPHID_InitRequestFrame',
    (CTAPHID_Frame, CTAP_InitRequestFrame), {})
CTAPHID_InitResponseFrame = type('CTAPHID_InitResponseFrame',
    (CTAPHID_Frame, CTAP_InitResponseFrame), {})
CTAPHID_MsgRequestFrame = type('CTAPHID_MsgRequestFrame',
    (CTAPHID_Frame, CTAP_MsgRequestFrame), {})
CTAPHID_MsgResponseFrame = type('CTAPHID_MsgResponseFrame',
    (CTAPHID_Frame, CTAP_MsgResponseFrame), {})
CTAPHID_PingFrame = type('CTAPHID_PingFrame', (CTAPHID_Frame, CTAP_PingFrame), {})
CTAPHID_WinkFrame = type('CTAPHID_WinkFrame', (CTAPHID_Frame, CTAP_WinkFrame), {})

