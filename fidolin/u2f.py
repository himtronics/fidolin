import enum, os, time

class CTAPHID_Capability(enum.IntFlag):
    WINK = 1
    LOCK = 2
    CBOR = 4
    NMSG = 8

class U2F_Command(enum.IntEnum):
    REGISTER = 0x01
    AUTHENTICATE = 0x02
    VERSION = 0x03

class U2F_Request(bytearray):
    def __init__(self, cla=0x00, ins=0x00, p1=0x00, p2=0x00, data=b''):
        payload_len = 4 + len(data)
        super().__init__(payload_len)
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.data = data

    @property
    def cla(self):
        return self[0]

    @cla.setter
    def cla(self, value):
        self[0] = value

    @property
    def ins(self):
        return self[1]

    @ins.setter
    def ins(self, value):
        self[1] = value

    @property
    def p1(self):
        return self[2]

    @p1.setter
    def p1(self, value):
        self[2] = value

    @property
    def p2(self):
        return self[3]

    @p1.setter
    def p2(self, value):
        self[3] = value

    @property
    def data(self):
        return self[4:]

    @data.setter
    def data(self, value):
        self[4:] = value


class U2F_StatusCode(enum.IntEnum):
    SW_NO_ERROR = 0x9000
    SW_CONDITIONS_NOT_SATISFIED = 0x6985
    SW_WRONG_DATA = 0x6A80
    SW_WRONG_LENGTH = 0x6700
    SW_CLA_NOT_SUPPORTED = 0x6E00
    SW_INS_NOT_SUPPORTED = 0x6D00

U2F_StatusMessage = {
    U2F_StatusCode.SW_NO_ERROR:
        'The command completed successfully without error.',
    U2F_StatusCode.SW_CONDITIONS_NOT_SATISFIED:
        'The request was rejected due to test-of-user-presence being required.',
    U2F_StatusCode.SW_WRONG_DATA:
        'The request was rejected due to an invalid key handle.',
    U2F_StatusCode.SW_WRONG_LENGTH:
        'The length of the request was invalid.',
    U2F_StatusCode.SW_CLA_NOT_SUPPORTED:
        'The Class byte of the request is not supported.',
    U2F_StatusCode.SW_INS_NOT_SUPPORTED:
        'The Instruction of the request is not supported.',
}

class U2FError(Exception):
    pass

class U2F_Response(bytearray):
    def __init__(self, data=b''):
        super().__init__(data)

    def check_sw(self):
        if self.sw != U2F_StatusCode.SW_NO_ERROR:
            raise U2FError('0x%x: %s' % (self.sw, U2FStatusMessage(self.sw)))

    @property
    def data(self):
        return self[:-2]

    @property
    def sw(self):
        return int.from_bytes(self[-2:], byteorder='big')
        
