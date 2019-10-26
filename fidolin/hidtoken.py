import enum, os, time

import hid

from .ctap import CTAP_Capability, CTAP_Command, CTAP_Frame, \
        CTAP_InitializationFrame,CTAP_ContinuationFrame
from .fidotoken import FidoToken

class HIDFidoToken(FidoToken):
    frame_size = 64
    frame_command_offset = 4
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
        print(init_response._initialization_frame)
        self.channel_id = init_response._initialization_frame.new_channel_id

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
        if not request._initialization_frame.is_valid_response(initial_response_frame):
            raise Exception('invalid response %s' % initial_response_frame)
        response_frames = [initial_response_frame]
        if initial_response_frame._bytecount is None:
            payload_len = initial_response_frame.bytecount
            frame_count = initial_response_frame.continuation_frame_count()
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

def hid_fido_tokens(addresses=[], check_usage=None):
    # adresses are of the form VVVV[PPPP[-S+]]] where VVVV is the hex
    # representation of the vendor id, PPPP the hex representation of
    # the product id and S+ the serial number string
    vendor_ids = {}
    for address in addresses:
        if len(address) < 4:
            raise Exception('invalid address %s' % address)
        vendor_id = int(address[:4], 16)
        if wendor_id not in vendor_ids:
            vendor_ids[vendor_id] = {}
        product_ids = vendor_ids[vendor_id]
        if len(address) >= 8:
            product_id = int(address[4:8], 16)
            if product_id not in product_ids:
                product_ids[product_id] = []
            if len(address) > 9:
                serial_numbers = product_ids[product_id]
                serial_numbers.append(address[9:])
    if check_usage is None and not addresses:
        check_usage = True
    hid_device_infos = hid.enumerate()
    for hid_device_info in hid_device_infos:
        device_vendor_id = hid_device_info['vendor_id']
        device_product_id = hid_device_info['product_id']
        device_serial_number = hid_device_info['serial_number']
        if vendor_ids:
            if device_vendor_id not in vendor_ids:
                continue
            product_ids = vendor_ids[device_vendor_id]
        else:
            product_ids = None
        if product_ids:
            if device_product_id not in product_ids:
                continue
            serial_numbers = product_ids[device_product_id]
        else:
            serial_numbers = None
        if serial_numbers:
            if device_serial_number not in serial_numbers:
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


