import enum, os, time

class CTAP_Command(enum.IntEnum):
    PING = 0x01
    MSG = 0x03
    LOCK = 0x04
    INIT = 0x06
    WINK = 0x08
    CANCEL = 0x11
    CBOR = 0x10
    ERROR = 0x3f
    KEEPALIVE = 0x3b

class CTAP_Capability(enum.IntFlag):
    WINK = 1
    LOCK = 2
    CBOR = 4
    NMSG = 8

class CTAP_Frame(bytearray):
    _bytecount = None
    _command_offset = 0

    def __init__(self, fido_token=None):
        if fido_token:
            super().__init__(fido_token.frame_size)
        else:
            super().__init__()
        self.fido_token = fido_token

    @property
    def init_payload_len(self):
        return self.fido_token.frame_size - self._command_offset - 3

    @property
    def cont_payload_len(self):
        return self.fido_token.frame_size - self._command_offset - 1

class CTAP_InitializationFrame(CTAP_Frame):
    _bytecount = None

    def __init__(self, fido_token=None, payload=None):
        super().__init__(fido_token)
        if fido_token:
            self.command_code = self._command_code()
            if self._bytecount is not None:
                self.bytecount = self._bytecount
            elif payload is not None:
                self.bytecount = len(payload)
                self.payload = payload[:self.init_payload_len]
            else:
                raise Exception('no bytecount')

    def _command_code(self):
        return 0x80 | self._command_id

    @property
    def command_id(self):
        return self.command_code & 0x7f

    @property
    def command_code(self):
        offset = self._command_offset
        return self[offset]

    @command_code.setter
    def command_code(self, value):
        offset = self._command_offset
        self[offset] = value

    @property
    def bytecount(self):
        offset = self._command_offset + 1
        bytecount_bytes = self[offset:offset+2]
        return int.from_bytes(bytecount_bytes, byteorder='big')

    @bytecount.setter
    def bytecount(self, value):
        offset = self._command_offset + 1
        self[offset:offset+2] = value.to_bytes(2, byteorder='big')

    @property
    def payload(self):
        offset = self._command_offset + 3
        payload_len = min(self.init_payload_len, self.bytecount)
        return self[offset:offset+payload_len]

