
from hashlib import sha256

from .u2f import (
    U2F_AuthControl,
    U2F_VersionRequest,
    U2F_RegisterRequest,
    U2F_AuthenticateRequest,
    U2F_Response,
)

class FidoToken(object):
    def u2f_request(self, u2f_request):
        u2f_response_bytes = self._u2f_request(u2f_request)
        u2f_response = U2F_Response.u2f_from_response(u2f_request,
            u2f_response_bytes)
        u2f_response.check_sw()
        return u2f_response

    def u2f_version(self):
        u2f_request = U2F_VersionRequest()
        u2f_response = self.u2f_request(u2f_request)
        return u2f_response

    def u2f_register(self, challenge, application):
        u2f_request = U2F_RegisterRequest(challenge, application)
        u2f_response = self.u2f_request(u2f_request)
        u2f_response.verify_signature(challenge, application)
        return u2f_response

    def u2f_authenticate(self, challenge, application, key_handle,
            control=U2F_AuthControl.ENFORCE_USER_PRESENCE_AND_SIGN):
        u2f_request = U2F_AuthenticateRequest(control, challenge, application,
            key_handle)
        u2f_response = self.u2f_request(u2f_request)
        return u2f_response 

