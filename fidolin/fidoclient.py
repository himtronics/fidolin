# standard python modules
import base64, secrets
from hashlib import pbkdf2_hmac, sha256
from operator import itemgetter

# python packages
from cryptography.fernet import Fernet
from ecdsa import NIST256p
from ecdsa.ecdsa import Signature

# local modules
from .u2f import U2F_AuthControl, u2f_parse_signature

class FidoClient(object):
    def __init__(self, fido_token, application):
        self.fido_token = fido_token
        self.application = application

    def u2f_register(self, challenge):
        u2f_response = self.fido_token.u2f_register(challenge, self.application)
        return u2f_response

    def u2f_authenticate(self, challenge, key_handle,
            control=U2F_AuthControl.ENFORCE_USER_PRESENCE_AND_SIGN):
        u2f_response = self.fido_token.u2f_authenticate(challenge, self.application,
            key_handle, control=control)
        #u2f_response.verify_signature(challenge, self.application, self.public_key)
        self.u2f_counter = u2f_response.counter
        return u2f_response 

    def u2f_encrypt(self, key, value, salt, iterations):
        '''
        encrypt the value for the given key and return a dictionary of values
        needed to decrypt the key with the fido_token. Note that only a hash
        of the public_key is returned, necessary for determining the real public
        key out of two possible values from the ec computation
        '''
        challenge = secrets.token_hex(32)
        u2f_response = self.u2f_register(challenge)
        secret = pbkdf2_hmac('sha256',
            u2f_response.public_key + key.encode('utf-8'),
            salt, iterations)
        fernet = Fernet(base64.urlsafe_b64encode(secret))
        return {
            'value_encrypted': fernet.encrypt(value.encode('utf-8')),
            'key_handle': u2f_response.key_handle,
            'public_key_hash': sha256(u2f_response.public_key).digest(),
        }

    def u2f_decrypt(self, key, value, salt, iterations):
        value_encrypted, key_handle, public_key_hash = itemgetter(
            'value_encrypted', 'key_handle', 'public_key_hash')(value)
        challenge = secrets.token_hex(32)
        u2f_response = self.u2f_authenticate(challenge, key_handle,
            control=U2F_AuthControl.DONT_ENFORCE_USER_PRESENCE_AND_SIGN)

        # with the signature and the message for which the signature was generated
        # two publik key candidates can be calculated
        r,s = u2f_parse_signature(u2f_response.signature)
        signature = Signature(r,s)
        message = u2f_response.message(challenge, self.application)
        message_hash = sha256(message).digest()
        message_int = int.from_bytes(message_hash, byteorder='big')
        public_keys = signature.recover_public_keys(message_int, NIST256p.generator)

        # compare the public key candidates against the stored hash of the public
        # key from the registration
        for public_key in public_keys:
            public_key_bytes = bytes([4]) + \
                 public_key.point.x().to_bytes(32, byteorder='big') + \
                 public_key.point.y().to_bytes(32, byteorder='big')
            if sha256(public_key_bytes).digest() == public_key_hash:
                 break
        else:
            raise Exception('no public key found')

        secret = pbkdf2_hmac('sha256', public_key_bytes + key.encode('utf-8'), salt,
            iterations)
        fernet = Fernet(base64.urlsafe_b64encode(secret))
        value_decrypted = fernet.decrypt(value_encrypted).decode('utf-8')
        return value_decrypted


