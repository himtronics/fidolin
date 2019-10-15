
from .u2f import U2F_AuthControl

class FidoClient(object):
    def __init__(self, application):
        self.application = application

    def u2f_register(self, fido_token, challenge):
        u2f_response = fido_token.u2f_register(challenge, self.application)
        self.key_handle = u2f_response.key_handle
        self.public_key = u2f_response.public_key
        return u2f_response

    def u2f_authenticate(self, fido_token, challenge,
            control=U2F_AuthControl.ENFORCE_USER_PRESENCE_AND_SIGN):
        u2f_response = fido_token.u2f_authenticate(challenge, self.application,
            self.key_handle, control=control)
        u2f_response.verify_signature(challenge, self.application, self.public_key)
        self.u2f_counter = u2f_response.counter
        return u2f_response 

