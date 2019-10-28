import enum, os, time

class CTAP_Command(enum.IntEnum):
    PING = 0x01
    KEEPALIVE = 0x02
    MSG = 0x03
    LOCK = 0x04
    INIT = 0x06
    WINK = 0x08
    CBOR = 0x10
    CANCEL = 0x11
    ERROR = 0x3f
    #KEEPALIVE = 0x3b

class CTAP_Capability(enum.IntFlag):
    WINK = 1
    LOCK = 2
    CBOR = 4
    NMSG = 8

class CTAP_Frame(bytearray):
    def __init__(self, frame_len, fido_token=None):
        super().__init__(frame_len)
        self.fido_token = fido_token

    @property
    def command_offset(self):
        return self.fido_token.frame_command_offset

    @property
    def init_payload_len(self):
        return self.fido_token.frame_max_len - self.command_offset - 3

    @property
    def cont_payload_len(self):
        return self.fido_token.frame_max_len - self.command_offset - 1

    @classmethod
    def from_data(cls, fido_token, data):
        self = cls(fido_token)
        self[:] = data
        return self

class CTAP_InitializationFrame(CTAP_Frame):
    _bytecount = None

    @classmethod
    def frame_len(cls, fido_token, payload):
        '''
        return the frame len required for this frame
        '''
        if fido_token is None:
            frame_len = 0
        elif payload:
            frame_len = min(len(payload) + fido_token.frame_command_offset + 3,  
                fido_token.frame_max_len)
        else:
            # command without payload
            frame_len = fido_token.frame_command_offset + 3
        return frame_len

    def __init__(self, fido_token=None, payload=None):
        frame_len = self.frame_len(fido_token, payload)
        super().__init__(frame_len, fido_token=fido_token)
        if fido_token:
            self.command_code = self._command_code()
            if self._bytecount is not None:
                self.bytecount = self._bytecount
            elif payload is not None:
                self.bytecount = len(payload)
                self.payload = payload[:self.init_payload_len]
            #else:
            #    raise Exception('no bytecount')

    def _command_code(self):
        return 0x80 | self._command_id

    @property
    def command_id(self):
        return self.command_code & 0x7f

    @property
    def command_code(self):
        offset = self.command_offset
        return self[offset]

    @command_code.setter
    def command_code(self, value):
        offset = self.command_offset
        self[offset] = value

    @property
    def bytecount(self):
        offset = self.command_offset + 1
        bytecount_bytes = self[offset:offset+2]
        return int.from_bytes(bytecount_bytes, byteorder='big')

    @bytecount.setter
    def bytecount(self, value):
        offset = self.command_offset + 1
        self[offset:offset+2] = value.to_bytes(2, byteorder='big')

    @property
    def payload(self):
        offset = self.command_offset + 3
        payload_len = min(self.init_payload_len, self.bytecount)
        return self[offset:offset+payload_len]

    @payload.setter
    def payload(self, value):
        offset = self.command_offset + 3
        self[offset:offset+len(value)] = value

    def is_valid_response(self, response_frame):
        return self.command_code == response_frame.command_code

    def continuation_frame_count(self):
        continuation_frame_count = (self.bytecount + 1) // self.cont_payload_len
        return continuation_frame_count

class CTAP_ContinuationFrame(CTAP_Frame):
    @classmethod
    def frame_len(cls, fido_token, payload, sequence):
        '''
        return the frame len required for this frame
        '''
        if fido_token is None:
            frame_len = 0
        elif payload:
            remaining_payload_len = len(payload) - \
                (fido_token.frame_max_len - fido_token.frame_command_offset - 3) - \
                sequence * (fido_token.frame_max_len - fido_token.frame_command_offset - 1)
            frame_len = min(remaining_payload_len + fido_token.frame_command_offset + 1,  
                fido_token.frame_max_len)
        else:
            # command without payload
            frame_len = fido_token.frame_command_offset + 1
        if payload:
            print('ContinuationFrame frame_len', len(payload), sequence, frame_len)
        return frame_len

    def __init__(self, fido_token=None, payload=None, sequence=None):
        frame_len = self.frame_len(fido_token, payload, sequence)
        super().__init__(frame_len, fido_token)
        if sequence is not None:
            self.sequence = sequence
        if payload is not None:
            self.payload = payload

    @property
    def sequence(self):
        offset = self.command_offset
        return self[offset]

    @sequence.setter
    def sequence(self, value):
        try:
            offset = self.command_offset
            self[offset] = value
        except:
            print('ZZZZ', len(self), offset, value)


    @property
    def payload(self):
        # bytecount not available on frame
        offset = self.command_offset + 1
        return self[offset:]

    @payload.setter
    def payload(self, value):
        offset = self.command_offset + 1
        payload_start = self.init_payload_len + \
            self.sequence * self.cont_payload_len
        payload_end = min(payload_start + self.cont_payload_len, len(value))
        self[offset:offset + payload_end - payload_start] = \
            value[payload_start:payload_end]

class CTAP_ErrorCode(enum.IntEnum):
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
    CTAP_ErrorCode.ERR_INVALID_CMD: 'The command in the request is invalid',
    CTAP_ErrorCode.ERR_INVALID_PAR: 'The parameter(s) in the request is invalid',
    CTAP_ErrorCode.ERR_INVALID_LEN: 'The length field (BCNT) is invalid for the request',
    CTAP_ErrorCode.ERR_INVALID_SEQ: 'The sequence does not match expected value',
    CTAP_ErrorCode.ERR_MSG_TIMEOUT: 'The message has timed out',
    CTAP_ErrorCode.ERR_CHANNEL_BUSY: 'The device is busy for the requesting channel',
    CTAP_ErrorCode.ERR_LOCK_REQUIRED: 'Command requires channel lock',
    CTAP_ErrorCode.ERR_INVALID_CHANNEL: 'CID is not valid.',
    CTAP_ErrorCode.ERR_OTHER: 'Unspecified error',
}

class CTAP_ErrorFrame(CTAP_InitializationFrame):
    _name = 'CTAP_Error'
    _command_id = 0x3f
    _bytecount = 1

    @property
    def error_code(self):
        offset = self.command_offset + 3
        return self[offset]

    @property
    def error_string(self):
        if self.error_code not in error_strings:
            raise Exception('únknown error code 0x%x' % self.error_code)
        return error_strings[self.error_code]

    def __str__(self):
        return 'Error 0x%x: %s: %s' % (self.error_code, self.error_string, self[:8])

class CTAP_KeepaliveStatusCode(enum.IntEnum):
    PROCESSING = 0x01
    TUP_NEEDED = 0x02

keepalive_status_strings = {
    CTAP_KeepaliveStatusCode.PROCESSING: 'processing',
    CTAP_KeepaliveStatusCode.TUP_NEEDED: 'tup needed',
}

class CTAP_KeepaliveFrame(CTAP_InitializationFrame):
    _name = 'CTAP_Keepalive'
    _command_id = CTAP_Command.KEEPALIVE
    _bytecount = 1
    @property
    def status_code(self):
        offset = self.command_offset + 3
        return self[offset]
    
    @property
    def status_code_string(self):
        if self.status_code not in status_code_strings:
            return 'rfu (%d)' % self.status_code
        return status_code_strings[self.status_code]

class CTAP_PingFrame(CTAP_InitializationFrame):
    _command_id = CTAP_Command.PING

class CTAP_PingFrames(list):
    def __init__(self, fido_token=None, payload=None):
        super().__init__(self)
        if fido_token:
            InitializationFrameClass = \
                fido_token.ctap_request_frame_class[CTAP_Command.PING]
            initialization_frame = InitializationFrameClass(fido_token, payload)
            self.append(initialization_frame)
            frame_count = initialization_frame.continuation_frame_count()
            ContinuationFrameClass = fido_token.ctap_continuation_class
            for sequence in range(frame_count):
                self.append(ContinuationFrameClass(fido_token, payload, sequence))

class CTAP_WinkFrame(CTAP_InitializationFrame):
    _name = 'CTAP_Wink'
    _command_id = 0x08
    _bytecount = 0

class CTAP_InitRequestFrame(CTAP_InitializationFrame):
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

class CTAP_InitResponseFrame(CTAP_InitRequestFrame):
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

class CTAP_MsgRequestFrame(CTAP_InitializationFrame):
    _command_id = CTAP_Command.MSG
    _bytecount = None

class CTAP_MsgResponseFrame(CTAP_MsgRequestFrame):
    pass

class CTAP_Request(object):
    def __init__(self, fido_token, command_id, payload=None):
        self.fido_token = fido_token
        self.command_id = command_id
        self.payload = payload
        self._initialization_frame = None

    def frames(self):
        if self._initialization_frame is None:
            CTAP_InitializationFrameClass = \
                self.fido_token.ctap_request_frame_class[self.command_id]
            self._initialization_frame = \
                CTAP_InitializationFrameClass(self.fido_token, self.payload)
        yield self._initialization_frame
        if self._initialization_frame._bytecount is not None:
            return
        frame_count = self._initialization_frame.continuation_frame_count()
        CTAP_ContinuationFrameClass = self.fido_token.ctap_continuation_frame_class
        for sequence in range(frame_count):
            yield CTAP_ContinuationFrameClass(self.fido_token, self.payload, sequence)

class CTAP_Response(object):
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

