import enum, os, time

import hid

from .ctap import CTAP_Command, CTAP_Request
from .ctaphid import CTAPHID_InitializationFrame, CTAPHID_ContinuationFrame, \
    CTAPHID_InitRequestFrame, CTAPHID_InitResponseFrame, \
    CTAPHID_PingFrame, CTAPHID_WinkFrame, CTAPHID_ErrorFrame, \
    CTAPHID_MsgRequestFrame, CTAPHID_MsgResponseFrame
from .fidotoken import FidoToken

class HIDFidoToken(FidoToken):
    ctap_initialization_frame_class = CTAPHID_InitializationFrame
    ctap_continuation_frame_class = CTAPHID_ContinuationFrame
    ctap_request_frame_class = {
        CTAP_Command.INIT: CTAPHID_InitRequestFrame,
        CTAP_Command.PING: CTAPHID_PingFrame,
        CTAP_Command.WINK: CTAPHID_WinkFrame,
        CTAP_Command.MSG: CTAPHID_MsgRequestFrame,
    }
    ctap_response_frame_class = {
        CTAP_Command.INIT: CTAPHID_InitResponseFrame,
        CTAP_Command.PING: CTAPHID_PingFrame,
        #CTAP_Command.KEEPALIVE: CTAP_KeepaliveFrame,
        CTAP_Command.WINK: CTAPHID_WinkFrame,
        CTAP_Command.MSG: CTAPHID_MsgResponseFrame,
        CTAP_Command.ERROR: CTAPHID_ErrorFrame,
    }
    frame_max_len = 64
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

    async def write_frame(self, frame):
        # the report id must be prepended
        data = b'\x00' + bytes(frame) + bytes(self.frame_max_len - len(frame))
        #print('write %d bytes: %s' % (len(data), data))
        self.hid_device.write(data)

    async def read_frame(self, continuation=False):
        data = self.hid_device.read(self.frame_max_len)
        #print('read %d bytes: %s' % (len(data), data))
        frame = self.frame_from_data(data, continuation)
        return frame

    def close(self):
        self.hid_device.close()

async def hid_fido_tokens(addresses=[], check_usage=None):
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


