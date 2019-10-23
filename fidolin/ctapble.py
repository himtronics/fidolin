import asyncio, enum, logging

from fidolin.fidotoken import FidoToken
from fidolin.ctap import CTAP_Capability, CTAP_Command

class CTAPBLE_Frame(bytearray):
    _bytecount = None

    def __init__(self, fido_token=None):
        self.fido_token = fido_token

    @property
    def init_payload_len(self):
        return self.fido_token.frame_size - 3

    @property
    def cont_payload_len(self):
        return self.fido_token.frame_size - 1


class CTAPBLE_InitializationFrame(BLE_Frame):
    def __init__(self, fido_token, command, payload)
        super().__init__(fido_token)

    def _command_code(self):
        return self._command_id | 0x80

    @property
    def command_id(self):
        return self.command_code & 0x7f

    @property
    def command_code(self):
        return self[0]

    @command_code.setter
    def command_code(self, value):
        self[0] = value

    @property
    def bytecount(self):
        return int.from_bytes(self[1:3], byteorder='big')

    @bytecount.setter
    def bytecount(self, value):
        self[1:3] = value.to_bytes(2, byteorder='big')

    @property
    def payload(self):
        payload_len = min(self.init_payload_len, self.bytecount)
        return self[3:3+payload_len]

    @payload.setter
    def payload(self, value):
        self[3:3+len(value)] = value

class CTAPBLE_PingFrame(CTAPBLE_InitializationFrame):
    _command_id = CTAP_Command.PING

class CTAPBLE_ContinuationFrame(BLE_Frame):
    def __init__(self, fido_token=None, payload=None, sequence=None):
        super().__init__(fido_token)
        if fido_token:
            self.sequence = sequence
            self.payload = payload

    @property
    def sequence(self):
        return self[0]

    @sequence.setter
    def sequence(self, value):
        self[0] = value

    @property
    def payload(self):
        # bytecount not available on packet
        return self[1:]

    @payload.setter
    def payload(self, value):
        payload_start = self.init_payload_len + self.sequence * self.cont_payload_len
        payload_end = min(payload_start + self.cont_payload_len, len(value))
        self[1:1 + payload_end - payload_start] = \
            value[payload_start:payload_end]
