import enum, os, time

from asn1crypto.core import load
from asn1crypto.x509 import Certificate
from ecdsa import VerifyingKey, BadSignatureError, NIST256p
from hashlib import sha256

from .apdu import APDU_Command, APDU_Response

class U2FError(Exception):
    pass

def der_len(data, offset):
    '''
    return the len of a der encoded structure at the given offset
    '''
    if data[offset] != 0x30:
        # universal (0), structured(1), sequence(16)
        raise U2FError('invalid certification type 0x%x' % data[offset])

    der_len = data[offset+1]
    if not der_len & 0x80:
        # this is the length
        der_len += 2
    elif der_len == 0x81:
        # length in one following octet
        der_len = data[offset+2] + 3
    elif der_len == 0x82:
        der_len = int.from_bytes(data[offset+2:offset+4], byteorder='big') + 4
    else:
        # longer than 65535 octets, or not DER at all
        raise U2FError('invalid length in certificate')
    return der_len

def u2f_parse_signature(signature):
    '''
    return a tuple r, s of integers contained in the DER encoded signature
    '''
    signature_asn1 = load(bytes(signature))
    r = signature_asn1[0].native
    s = signature_asn1[1].native
    return r, s

def u2f_verify_signature(signature, message, public_key):
    '''
    verify the signature contained in the response against the
    message from which it was constructed and a public key provided
    by the token
    '''
    # the public key is represented in uncompressed x,y notation,
    # with 0x04 as byte 0 and x and y each 32 bytes, 65 bytes in total
    if public_key[0] != 0x04:
        raise Exception('invalid ECBitArray')
    # VerifyKey wants just x and y in 64 bytes
    verifying_key = VerifyingKey.from_string(public_key[1:],
            curve=NIST256p, hashfunc=sha256)
    # the signature is DER encoded as 2 integers but the verify function
    # needs a 64 byte representation of these 2 integers
    r, s = u2f_parse_signature(signature)
    ecdsa_signature = r.to_bytes(32, byteorder='big') + \
        s.to_bytes(32, byteorder='big')
    verifying_key.verify(ecdsa_signature, message)

class U2F_Command(enum.IntEnum):
    REGISTER = 0x01
    AUTHENTICATE = 0x02
    VERSION = 0x03

class U2F_Request(APDU_Command):
    pass

class U2F_Response(APDU_Response):
    @classmethod
    def u2f_from_response(cls, request, response_bytes):
        cls = U2F_Response_by_command[request.ins]
        self = cls.from_response(response_bytes)
        return self

class U2F_VersionRequest(U2F_Request):
    def __init__(self):
        super().__init__(ins=U2F_Command.VERSION)

class U2F_VersionResponse(U2F_Response):
    @property
    def version(self):
        return self.data.decode('UTF-8')

    def __str__(self):
        return self.version

class U2F_RegisterRequest(U2F_Request):
    def __init__(self, challenge, application):
        challenge_data = sha256(challenge.encode('utf-8')).digest()
        application_data = sha256(application.encode('utf-8')).digest()
        data = challenge_data + application_data
        super().__init__(ins=U2F_Command.REGISTER, data=data)

class U2F_RegisterResponse(U2F_Response):
    pk_offset = 1
    pk_len = 65
    kh_offset = pk_offset + pk_len + 1

    @property
    def reserved(self):
        return self[0]

    @property
    def public_key(self):
        offset = self.pk_offset
        return self[offset:offset+self.pk_len]

    @property
    def kh_len(self):
        return self[self.kh_offset-1]

    @property
    def key_handle(self):
        offset = self.kh_offset
        return self[offset:offset+self.kh_len]

    @property
    def ac_offset(self):
        return self.kh_offset + self.kh_len

    @property
    def ac_len(self):
        '''
        return length of DER-encoded X509 certificate
        '''
        return der_len(self, self.ac_offset)

    @property
    def attestation_certificate(self):
        offset = self.ac_offset
        return bytes(self[offset:offset+self.ac_len])

    @property
    def sig_offset(self):
        return self.ac_offset + self.ac_len

    @property
    def sig_len(self):
        '''
        return length of DER-encoded signature
        '''
        return der_len(self, self.sig_offset)

    @property
    def signature(self):
        offset = self.sig_offset
        return self[offset:offset+self.sig_len]

    def verify_signature(self, challenge, application):
        challenge_data = sha256(challenge.encode('utf-8')).digest()
        application_data = sha256(application.encode('utf-8')).digest()
        message = b'\0' + application_data + challenge_data + \
            self.key_handle + self.public_key
        certificate = Certificate.load(self.attestation_certificate)
        # the public key is represented in uncompressed x,y notation,
        # with 0x04 as byte 0 and x and y each 32 bytes, 65 bytes in total
        public_key = bytes(certificate.public_key['public_key'])
        u2f_verify_signature(self.signature, message, public_key)

    def __str__(self):
        return '\n'.join([
                'U2F_RegisterResponse:',
                '    reserved: 0x%x' % self.reserved,
                '    public_key: %s' % self.public_key.hex(),
                '    key_handle_len: %d' % self.kh_len,
                '    key_handle: %s' % self.key_handle.hex(),
                '    attestation_certificate: %s' % self.attestation_certificate.hex(),
                '    signature: %s' % self.signature.hex(),
        ])
        
class U2F_AuthControl(enum.IntEnum):
    ENFORCE_USER_PRESENCE_AND_SIGN = 0x03
    CHECK_ONLY = 0x07
    DONT_ENFORCE_USER_PRESENCE_AND_SIGN = 0x08

class U2F_AuthenticateRequest(U2F_Request):
    def __init__(self, control, challenge, application, key_handle):
        challenge_data = sha256(challenge.encode('utf-8')).digest()
        application_data = sha256(application.encode('utf-8')).digest()
        data = challenge_data + application_data + \
            bytes([len(key_handle)]) + key_handle
        super().__init__(ins=U2F_Command.AUTHENTICATE, p1=control, data=data)


class U2F_AuthenticateResponse(U2F_Response):
    co_offset = 1
    co_len = 4
    sig_offset = 5

    @property
    def user_presence(self):
        return self[0]

    @property
    def counter(self):
        offset = self.co_offset
        return int.from_bytes(self[offset:offset+self.co_len], byteorder='big')

    @property
    def sig_len(self):
        '''
        return length of DER-encoded signature
        '''
        return der_len(self, self.sig_offset)

    @property
    def signature(self):
        offset = self.sig_offset
        return self[offset:offset+self.sig_len]

    def message(self, challenge, application):
        challenge_data = sha256(challenge.encode('utf-8')).digest()
        application_data = sha256(application.encode('utf-8')).digest()
        message = application_data + bytes([self.user_presence]) + \
            self.counter.to_bytes(4, byteorder='big') + challenge_data
        return message

    def verify_signature(self, challenge, application, public_key):
        message = self.message(challenge, application)
        u2f_verify_signature(self.signature, message, public_key)
        
U2F_Response_by_command = {
    U2F_Command.REGISTER: U2F_RegisterResponse,
    U2F_Command.AUTHENTICATE: U2F_AuthenticateResponse,
    U2F_Command.VERSION: U2F_VersionResponse,
}
