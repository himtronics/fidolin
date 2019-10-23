import enum, os, time

import hid

from .ctap import CTAP_Capability, CTAP_Command, CTAP_Frame
from .fidotoken import FidoToken
from .u2f import U2F_Command, U2F_Request, U2F_Response

HID_FRAME_SIZE = 64
HID_INIT_PAYLOAD_LEN = HID_FRAME_SIZE - 7
HID_CONT_PAYLOAD_LEN = HID_FRAME_SIZE - 5

class CTAPHID_Frame(CTAP_Frame):
    _command_offset = 4

    def __init__(self, fido_token=None):
        super().__init__(fido_token)
        if fido_token:
            self.channel_id = fido_token.channel_id

    @property
    def channel_id(self):
        return int.from_bytes(self[0:4], byteorder='big')

    @channel_id.setter
    def channel_id(self, value):
        self[0:4] = value.to_bytes(4, byteorder='big')

    @classmethod
    def from_data(cls, fido_token, data):
        self = cls()
        self[:] = data
        return self

class CTAPHID_InitializationFrame(CTAPHID_Frame):
    _bytecount = None

    def __init__(self, fido_token=None, payload=None):
        super().__init__(fido_token)
        if fido_token:
            self.command_code = self._command_code()
            if self._bytecount is not None:
                self.bytecount = self._bytecount
            elif payload is not None:
                self.bytecount = len(payload)
                self.payload = payload[:57]
            else:
                raise Exception('no bytecount')

    def _command_code(self):
        return 0x80 | self._command_id

    @property
    def command_id(self):
        return self.command_code & 0x7f

    @property
    def command_code(self):
        return self[4]

    @command_code.setter
    def command_code(self, value):
        self[4] = value

    @property
    def bytecount(self):
        return int.from_bytes(self[5:7], byteorder='big')

    @bytecount.setter
    def bytecount(self, value):
        self[5:7] = value.to_bytes(2, byteorder='big')

    @property
    def payload(self):
        payload_len = min(57, self.bytecount)
        return self[7:7+payload_len]

    @payload.setter
    def payload(self, value):
        self[7:7+len(value)] = value

    def is_valid_response(self, response_frame):
        return self.command_code == response_frame.command_code

class CTAPHID_ContinuationFrame(CTAPHID_Frame):
    _bytecount = None

    def __init__(self, fido_token=None, payload=None, sequence=None):
        super().__init__(fido_token)
        if fido_token:
            self.sequence = sequence
            self.payload = payload

    @property
    def sequence(self):
        return self[4]

    @sequence.setter
    def sequence(self, value):
        self[4] = value

    @property
    def payload(self):
        # bytecount not available on frame
        return self[5:]

    @payload.setter
    def payload(self, value):
        payload_start = HID_INIT_PAYLOAD_LEN + self.sequence * HID_CONT_PAYLOAD_LEN
        payload_end = min(payload_start + HID_CONT_PAYLOAD_LEN, len(value))
        self[5:5 + payload_end - payload_start] = \
            value[payload_start:payload_end]

def continuation_frame_count(payload_len):
    continuation_frame_count = (payload_len + 1) // HID_CONT_PAYLOAD_LEN
    return continuation_frame_count

class CTAPHID_PingFrame(CTAPHID_InitializationFrame):
    _command_id = CTAP_Command.PING

class CTAPHID_PingFrames(list):
    def __init__(self, fido_token=None, payload=None):
        super().__init__(self)
        if fido_token:
            self.append(CTAPHID_PingFrame(fido_token, payload))
            frame_count = continuation_frame_count(len(payload))
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
        self._initialisation_frame = None
    def frames(self):
        if self._initialisation_frame is None:
            InitializationFrame = \
                CTAPHID_RequestFrameByCommandId[self.command_id]
            self._initialisation_frame = \
                InitializationFrame(self.fido_token, self.payload)
        yield self._initialisation_frame
        if self._initialisation_frame._bytecount is not None:
            return
        frame_count = continuation_frame_count(len(self.payload))
        for sequence in range(frame_count):
            yield CTAPHID_ContinuationFrame(self.fido_token, self.payload, sequence)

class CTAPHID_Response(object):
    def __init__(self, fido_token, command_id, payload=None):
        self.fido_token = fido_token
        self.command_id = command_id
        self.payload = payload
        self._initialisation_frame = None

    @classmethod
    def from_frames(cls, fido_token, frames):
        initialisation_frame = frames[0]
        payload = None
        if initialisation_frame._bytecount is None:
            payload = b''.join(frame.payload for frame in frames)[:initialisation_frame.bytecount]
        response = cls(fido_token, initialisation_frame.command_id, payload)
        response._initialisation_frame = initialisation_frame
        return response


#CTAPCommands = [
#    CTAPCommand('CTAPHID_MSG',0x03,0),
#    CTAPCommand('CTAPHID_LOCK',0x04,0),
#    CTAPCommand('CTAPHID_INIT',0x06,0),
#    CTAPCommand('CTAPHID_WINK',0x08,0),
#    CTAPCommand('CTAPHID_CBOR',0x10,0),
#    CTAPCommand('CTAPHID_CANCEL',0x11,0),
#    CTAPCommand('CTAPHID_ERROR',0x3f,0),
#    CTAPCommand('CTAPHID_KEEPALIVE',0x3b,0),
#]

class HIDFidoToken(FidoToken):
    frame_size = 64
    def __init__(self, hid_device, hid_device_info):
        self.channel_id = 0xffffffff
        self.hid_device = hid_device
        self.hid_device_info = hid_device_info
    def __str__(self):
        return '%s - %s (0x%x, 0x%x), serial: %s' % (
                self.hid_device.manufacturer,
                self.hid_device.product,
                self.hid_device_info['vendor_id'],
                self.hid_device_info['product_id'],
                '')
                #self.hid_device.serial)

    def initialize(self):
        init_request = CTAPHID_Request(self, CTAP_Command.INIT)
        init_response = self.request(init_request)
        print(init_response._initialisation_frame)
        self.channel_id = init_response._initialisation_frame.new_channel_id

    def write_frame(self, frame):
        # the report id must be prepended
        data = b'\x00' + bytes(frame)
        #print('write %d bytes: %s' % (len(data), data))
        self.hid_device.write(data)

    def read_frame(self, continuation=False):
        data = self.hid_device.read(HID_FRAME_SIZE)
        #print('read %d bytes: %s' % (len(data), data))
        frame = self.frame_from_data(data, continuation)
        return frame

    def frame_from_data(self, data, continuation):
        if continuation:
            sequence = data[4]
            if sequence & 0x80:
                raise Exception('invalid sequence %d' % sequence)
            Frame = CTAPHID_ContinuationFrame
        else:
            command_id = data[4] & 0x7f
            if command_id not in CTAPHID_ResponseFrameByCommandId:
                raise Exception('invalid command in data: 0x%x' % command_id)
            Frame = CTAPHID_ResponseFrameByCommandId[command_id]
        frame = Frame.from_data(self, data)
        return frame

    def request(self, request):
        for frame in request.frames():
            self.write_frame(frame)
        initial_response_frame = self.read_frame()
        if not request._initialisation_frame.is_valid_response(initial_response_frame):
            raise Exception('invalid response %s' % initial_response_frame)
        response_frames = [initial_response_frame]
        if initial_response_frame._bytecount is None:
            payload_len = initial_response_frame.bytecount
            frame_count = continuation_frame_count(payload_len)
            for sequence in range(frame_count):
                continuation_response_frame = \
                    self.read_frame(continuation=True)
                response_frames.append(continuation_response_frame)
        response = CTAPHID_Response.from_frames(self, response_frames)
        return response

    def _u2f_request(self, u2f_request):
        '''
        transport specific handling of a U2F request returning the raw bytes
        of the response
        '''
        msg_request = CTAPHID_Request(self, CTAP_Command.MSG,
            u2f_request)
        msg_response = self.request(msg_request)
        return msg_response.payload

    def close(self):
        self.hid_device.close()

def hid_fido_tokens(vendor_id=None, product_id=None, check_usage=None):
    if check_usage is None and vendor_id is None and product_id is None:
        check_usage = True
    hid_device_infos = hid.enumerate()
    for hid_device_info in hid_device_infos:
        device_vendor_id = hid_device_info['vendor_id']
        device_product_id = hid_device_info['product_id']
        device_serial_number = hid_device_info['serial_number']
        if vendor_id and vendor_id != device_vendor_id:
            continue
        if product_id and product_id != device_product_id:
            continue
        if check_usage:
            usage_page = hid_device_info['usage_page']
            usage = hid_device_info['usage']
            if usage_page != 0xf1d0 or usage != 0x01:
                continue
        try:
            hid_device = hid.Device(device_vendor_id, device_product_id)#, serial_number)
        except:
            print('failed to open device 0x%x 0x%x' % (device_vendor_id, device_product_id))
            raise
        hid_fido_token = HIDFidoToken(hid_device, hid_device_info)
        yield hid_fido_token


