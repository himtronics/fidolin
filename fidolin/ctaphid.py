import enum, os, time

from .ctap import CTAP_Capability, CTAP_Command, CTAP_Frame, \
        CTAP_InitializationFrame,CTAP_ContinuationFrame
from .fidotoken import FidoToken
from .u2f import U2F_Command, U2F_Request, U2F_Response

class CTAPHID_Frame(object):
    @property
    def channel_id(self):
        return int.from_bytes(self[0:4], byteorder='big')

    @channel_id.setter
    def channel_id(self, value):
        self[0:4] = value.to_bytes(4, byteorder='big')

class CTAPHID_InitializationFrame(CTAP_InitializationFrame, CTAPHID_Frame):
    def __init__(self, fido_token=None, payload=None):
        super().__init__(fido_token, payload)
        if fido_token:
            self.channel_id = fido_token.channel_id

class CTAPHID_ContinuationFrame(CTAP_ContinuationFrame, CTAPHID_Frame):
    def __init__(self, fido_token=None, payload=None, sequence=None):
        super().__init__(fido_token, payload, sequence)
        if fido_token:
            self.channel_id = fido_token.channel_id

class CTAPHID_PingFrame(CTAPHID_InitializationFrame):
    _command_id = CTAP_Command.PING

class CTAPHID_PingFrames(list):
    def __init__(self, fido_token=None, payload=None):
        super().__init__(self)
        if fido_token:
            initialization_frame = CTAPHID_PingFrame(fido_token, payload)
            self.append(initialization_frame)
            frame_count = initialization_frame.continuation_frame_count()
            for sequence in range(frame_count):
                self.append(CTAPHID_ContinuationFrame(fido_token, payload, sequence))

class CTAPHID_WinkFrame(CTAPHID_InitializationFrame):
    _name = 'CTAPHID_Wink'
    _command_id = 0x08
    _bytecount = 0

ERR_INVALID_CMD = 0x01
ERR_INVALID_PAR = 0x02
ERR_INVALID_LEN = 0x03
ERR_INVALID_SEQ = 0x04
ERR_MSG_TIMEOUT = 0x05
ERR_CHANNEL_BUSY = 0x06
ERR_LOCK_REQUIRED = 0x0A
ERR_INVALID_CHANNEL = 0x0B
ERR_OTHER = 0x7F
error_strings = {
    ERR_INVALID_CMD: 'The command in the request is invalid',
    ERR_INVALID_PAR: 'The parameter(s) in the request is invalid',
    ERR_INVALID_LEN: 'The length field (BCNT) is invalid for the request',
    ERR_INVALID_SEQ: 'The sequence does not match expected value',
    ERR_MSG_TIMEOUT: 'The message has timed out',
    ERR_CHANNEL_BUSY: 'The device is busy for the requesting channel',
    ERR_LOCK_REQUIRED: 'Command requires channel lock',
    ERR_INVALID_CHANNEL: 'CID is not valid.',
    ERR_OTHER: 'Unspecified error',
}

class CTAPHID_ErrorFrame(CTAPHID_InitializationFrame):
    _name = 'CTAPHID_Error'
    _command_id = 0x3f
    _bytecount = 1

    @property
    def error_code(self):
        return self[7]

    @property
    def error_string(self):
        if self.error_code not in error_strings:
            raise Exception('únknown error code 0x%x' % self.error_code)
        return error_strings[self.error_code]

    def __str__(self):
        return 'Error 0x%x: %s: %s' % (self.error_code, self.error_string, self[:8])

class CTAPHID_InitRequestFrame(CTAPHID_InitializationFrame):
    _command_id = CTAP_Command.INIT
    _bytecount = 8
    
    def __init__(self, fido_token=None, payload=None):
        super().__init__(fido_token, payload=None)
        if fido_token:
            self.nonce = os.urandom(8)

    @property
    def nonce(self):
        return self[7:15]

    @nonce.setter
    def nonce(self, value):
        self[7:15] = value

class CTAPHID_InitResponseFrame(CTAPHID_InitRequestFrame):
    _bytecount = 17
    
    @classmethod
    def from_data(cls, fido_token, data):
        self = super().from_data(fido_token, data)
        if self.command_code != self._command_code():
            raise Exception('invalid commande code:', data)
        if self._bytecount is not None and self.bytecount != self._bytecount:
            raise Exception('invalid bytecount')
        return self

    @property
    def new_channel_id(self):
        return int.from_bytes(self[15:19], byteorder='big')

    @property
    def ctap_version(self):
        return self[19]
    @property
    def device_major_version(self):
        return self[20]
    @property
    def device_minor_version(self):
        return self[21]
    @property
    def device_build_version(self):
        return self[22]
    @property
    def capabilities(self):
        return CTAP_Capability(self[23])

    def __str__(self):
        return '\n'.join([
                'command: 0x%x' % self.command_code,
                'nonce: %s' % self.nonce,
                'new_channel_id: 0x%.8x' % self.new_channel_id,
                'device version: %s, %s, %s' % (
                    self.device_major_version,
                    self.device_minor_version,
                    self.device_build_version),
                'capabilities: %s' % self.capabilities,
        ])

class CTAPHID_MsgRequestFrame(CTAPHID_InitializationFrame):
    _command_id = CTAP_Command.MSG
    _bytecount = None

class CTAPHID_MsgResponseFrame(CTAPHID_MsgRequestFrame):
    pass

CTAPHID_RequestFrames = [
    CTAPHID_PingFrame,
    CTAPHID_InitRequestFrame,
    CTAPHID_WinkFrame,
    CTAPHID_MsgRequestFrame,
]
CTAPHID_RequestFrameByCommandId = \
    dict((p._command_id, p) for p in CTAPHID_RequestFrames)
CTAPHID_ResponseFrames = [
    CTAPHID_PingFrame,
    CTAPHID_InitResponseFrame,
    CTAPHID_WinkFrame,
    CTAPHID_ErrorFrame,
    CTAPHID_MsgResponseFrame,
]
CTAPHID_ResponseFrameByCommandId = \
    dict((p._command_id, p) for p in CTAPHID_ResponseFrames)

class CTAPHID_Request(object):
    def __init__(self, fido_token, command_id, payload=None):
        self.fido_token = fido_token
        self.command_id = command_id
        self.payload = payload
        self._initialization_frame = None
    def frames(self):
        if self._initialization_frame is None:
            InitializationFrame = \
                CTAPHID_RequestFrameByCommandId[self.command_id]
            self._initialization_frame = \
                InitializationFrame(self.fido_token, self.payload)
        yield self._initialization_frame
        if self._initialization_frame._bytecount is not None:
            return
        frame_count = self._initialization_frame.continuation_frame_count()
        for sequence in range(frame_count):
            yield CTAPHID_ContinuationFrame(self.fido_token, self.payload, sequence)

class CTAPHID_Response(object):
    def __init__(self, fido_token, command_id, payload=None):
        self.fido_token = fido_token
        self.command_id = command_id
        self.payload = payload
        self._initialization_frame = None

    @classmethod
    def from_frames(cls, fido_token, frames):
        initialization_frame = frames[0]
        payload = None
        if initialization_frame._bytecount is None:
            payload = b''.join(frame.payload for frame in frames)[:initialization_frame.bytecount]
        response = cls(fido_token, initialization_frame.command_id, payload)
        response._initialization_frame = initialization_frame
        return response



