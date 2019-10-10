import enum, os, time

class APDUError(Exception):
    pass

class APDU_Command(bytearray):
    def __init__(self, cla=0x00, ins=0x00, p1=0x00, p2=0x00, data=b''):
        if len(data) > 65536:
            raise APDUError('data len > 65536')
        payload_len = 7 + len(data)
        super().__init__(payload_len)
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.lc = len(data)
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

    @p2.setter
    def p2(self, value):
        self[3] = value

    @property
    def lc(self):
        return int.from_bytes(self[4:7], byteorder='big')

    @lc.setter
    def lc(self, value):
        self[4:7] = value.to_bytes(3, byteorder='big')

    @property
    def data(self):
        return self[7:]

    @data.setter
    def data(self, value):
        self.lc = len(value)
        self[7:] = value

    def __str__(self):
        return '\n'.join([
                'APDU_Request:',
                '    cla: 0x%x' % self.cla,
                '    ins: 0x%x' % self.ins,
                '    p1: 0x%x' % self.p1,
                '    p2: 0x%x' % self.p2,
                '    lc: %d' % self.lc,
                '    data: %s' % self.data,
        ])


class APDU_StatusWord(enum.IntEnum):
    SW_NO_ERROR = 0x9000
    SW_CONDITIONS_NOT_SATISFIED = 0x6985
    SW_WRONG_DATA = 0x6A80
    SW_WRONG_LENGTH = 0x6700
    SW_CLA_NOT_SUPPORTED = 0x6E00
    SW_INS_NOT_SUPPORTED = 0x6D00

APDU_StatusMessage = {
    APDU_StatusWord.SW_NO_ERROR:
        'The command completed successfully without error.',
    APDU_StatusWord.SW_CONDITIONS_NOT_SATISFIED:
        'The request was rejected due to test-of-user-presence being required.',
    APDU_StatusWord.SW_WRONG_DATA:
        'The request was rejected due to an invalid key handle.',
    APDU_StatusWord.SW_WRONG_LENGTH:
        'The length of the request was invalid.',
    APDU_StatusWord.SW_CLA_NOT_SUPPORTED:
        'The Class byte of the request is not supported.',
    APDU_StatusWord.SW_INS_NOT_SUPPORTED:
        'The Instruction of the request is not supported.',
}

class APDU_Response(bytearray):
    def __init__(self, data=b'', sw=APDU_StatusWord.SW_NO_ERROR):
        if isinstance(sw, int):
            sw = sw.to_bytes(2, byteorder='big')
        super().__init__(data+sw)

    @classmethod
    def from_response(cls, response):
        data, sw = response[:-2], response[-2:]
        self = cls(data, sw)
        return self

    def check_sw(self):
        if self.sw != APDU_StatusWord.SW_NO_ERROR:
            raise APDUError('0x%x: %s' % (self.sw, APDU_StatusMessage[self.sw]))

    @property
    def data(self):
        return self[:-2]

    @property
    def sw(self):
        return int.from_bytes(self[-2:], byteorder='big')
        
