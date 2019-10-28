
from hashlib import sha256

from .u2f import (
    U2F_AuthControl,
    U2F_VersionRequest,
    U2F_RegisterRequest,
    U2F_AuthenticateRequest,
    U2F_Response,
)

from .ctap import CTAP_Command, CTAP_Request, CTAP_Response

class FidoToken(object):
    async def u2f_request(self, u2f_request):
        ctap_request = self.ctap_request(CTAP_Command.MSG, u2f_request)
        ctap_response = await self.request(ctap_request)
        u2f_response = U2F_Response.u2f_from_response(u2f_request,
            ctap_response.payload)
        u2f_response.check_sw()
        return u2f_response

    async def u2f_version(self):
        u2f_request = U2F_VersionRequest()
        u2f_response = await self.u2f_request(u2f_request)
        return u2f_response

    async def u2f_register(self, challenge, application):
        u2f_request = U2F_RegisterRequest(challenge, application)
        u2f_response = await self.u2f_request(u2f_request)
        u2f_response.verify_signature(challenge, application)
        return u2f_response

    async def u2f_authenticate(self, challenge, application, key_handle,
            control=U2F_AuthControl.ENFORCE_USER_PRESENCE_AND_SIGN):
        u2f_request = U2F_AuthenticateRequest(control, challenge, application,
            key_handle)
        u2f_response = await self.u2f_request(u2f_request)
        return u2f_response 

    def ctap_request(self, ctap_command, payload=None):
        response = CTAP_Request(self, ctap_command, payload=payload)
        return response

    async def request(self, request):
        for frame in request.frames():
            await self.write_frame(frame)
        while True:
            initial_response_frame = await self.read_frame()
            if initial_response_frame.command_id == CTAP_Command.KEEPALIVE:
                print('%s: continuing' % initial_response_frame)
                continue
            if not request._initialization_frame.is_valid_response(initial_response_frame):
                raise Exception('invalid response %s' % initial_response_frame)
            break
        response_frames = [initial_response_frame]
        if initial_response_frame._bytecount is None:
            payload_len = initial_response_frame.bytecount
            frame_count = initial_response_frame.continuation_frame_count()
            for sequence in range(frame_count):
                continuation_response_frame = \
                    await self.read_frame(continuation=True)
                response_frames.append(continuation_response_frame)
        response = CTAP_Response.from_frames(self, response_frames)
        return response

    def frame_from_data(self, data, continuation):
        if continuation:
            sequence = data[self.frame_command_offset]
            if sequence & 0x80:
                raise Exception('invalid sequence %d' % sequence)
            Frame = self.ctap_continuation_frame_class
        else:
            command_id = data[self.frame_command_offset] & 0x7f
            if command_id not in self.ctap_response_frame_class:
                raise Exception('invalid command in data: 0x%x' % command_id)
            Frame = self.ctap_response_frame_class[command_id]
        frame = Frame.from_data(self, data)
        return frame

