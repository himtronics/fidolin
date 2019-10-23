import asyncio, enum, logging

from bleak import BleakClient, discover
from bleak import uuids as bleak_uuids
#address = 'B29D9B51-EB91-4135-BB1A-B85204F480EF'
address = 'B9B20796-F137-43D6-BE97-F4F2060EF498'

from fidolin.fidotoken import FidoToken
from fidolin.ctap import CTAP_Capability, CTAP_Command
#from fidolin.ctapble import CTAPBLE_Capability, CTAP_Command


class BLE_DeviceType(enum.IntEnum):
    FIDO = 0xf1d0

class BLE_ServiceType(enum.IntEnum):
    DeviceInfo = 0x180a
    BatteryInfo = 0x180f
    FIDO = 0xfffd

class BLE_Characteristic(enum.IntEnum):
    Manufacturer = 0x2a29
    ModelNumber = 0x2a24
    FirmwareRevision = 0x2a26
    SoftwareRevision = 0x2a28
    BatteryLevel = 0x2a19
    # U2F specific characteristics
    u2fControlPoint = 0xfff1
    u2fStatus = 0xfff2
    u2fControlPointLength = 0xfff3
    u2fServiceRevision = SoftwareRevision
    u2fServiceRevisionBitfield = 0xfff4

class BLE_U2FServiceRevision(enum.IntFlag):
    u2fServiceRevision_1_1 = 0x80
    u2fServiceRevision_1_2 = 0x40

BLE_U2FCharacteristics = {
    BLE_Characteristic.u2fControlPoint: 'U2F Control Point',
    BLE_Characteristic.u2fStatus: 'U2F Status',
    BLE_Characteristic.u2fControlPointLength: 'U2F Control Point Length',
    BLE_Characteristic.u2fServiceRevision: 'U2F Service Revision',
    BLE_Characteristic.u2fServiceRevisionBitfield: 'U2F Service Revision Bitfield',
}

def uuid_name(uuid):
    if uuid in BLE_U2FCharacteristics:
        return BLE_U2FCharacteristics[uuid]
    if uuid in bleak_uuids.uuid16_dict:
        return bleak_uuids.uuid16_dict[uuid]
    return 'unknown charcteristic 0x%x' % uuid

class BLEClient(BleakClient):
    _characteristic_ids = [
        BLE_Characteristic.Manufacturer,
        BLE_Characteristic.ModelNumber,
        BLE_Characteristic.FirmwareRevision,
        #BLE_Characteristic.SoftwareRevision,
        BLE_Characteristic.BatteryLevel,
    ]
    def __init__(self, address, loop=None):
        print('BLEClient1')
        super().__init__(address, loop=loop)
        print('BLEClient2')
        self._characteristics = {}

    async def get_gatt_characteristics(self, characteristic_ids=None):
        if characteristic_ids is None:
            characteristic_ids = self._characteristic_ids
        for service in self.services:
            service_type = service.uuid
            for characteristic in service.characteristics:
                uuid = characteristic.uuid
                if len(uuid) != 4:
                    uuid = uuid[4:8]
                characteristic_id = int(uuid, 16)
                properties = characteristic.properties
                if characteristic_id not in characteristic_ids:
                    print("ignoring characteristic {0} ({1}): {2}".format(
                        characteristic_id, ",".join(properties),
                        characteristic.description))
                    continue
                if "read" in characteristic.properties:
                    value = bytes(await self.read_gatt_char(characteristic.uuid))
                else:
                    value = None
                self.add_gatt_characteristic(characteristic_id, characteristic, value)
                #for descriptor in char.descriptors:
                #    value = await client.read_gatt_descriptor(descriptor.handle)
                #    log.info(
                #        "\t\t[Descriptor] {0}: (Handle: {1}) | Value: {2} ".format(
                #            descriptor.uuid, descriptor.handle, bytes(value)
                #        )
                #    )

    def add_gatt_characteristic(self, characteristic_id, characteristic, value):
        self._characteristics[characteristic_id] = value

    @property
    def firmware_revision(self):
        return self._characteristics[BLE_Characteristic.FirmwareRevision].decode('utf-8')

    @property
    def manufacturer(self):
        print(self._characteristics)
        return self._characteristics[BLE_Characteristic.Manufacturer].decode('utf-8')

    @property
    def model_number(self):
        return self._characteristics[BLE_Characteristic.ModelNumber].decode('utf-8')

    @property
    def battery_level(self):
        return int.from_bytes(self._characteristics[BLE_Characteristic.BatteryLevel], byteorder='big')

    def __str__(self):
        strings = []
        for characteristic_id, value in self._characteristics.items():
            strings.append('%s: %s' % (uuid_name(characteristic_id), value))
        return '\n'.join(strings)

class BLEFidoDevice(BLEClient):
    _characteristic_ids = BLEClient._characteristic_ids + [
        BLE_Characteristic.u2fControlPoint,
        BLE_Characteristic.u2fStatus,
        BLE_Characteristic.u2fControlPointLength,
        #BLE_Characteristic.u2fServiceRevision,
        BLE_Characteristic.u2fServiceRevisionBitfield,
    ]
    def is_fido_device(self):
        print('is_fido_device')
        for service in self.services:
            print('is_fido_device', service, service.uuid)
            if len(service.uuid) <= 4:
                continue
            service_type = int(service.uuid[4:8], 16)
            print('service_type 0x%x 0x%x' % (service_type, BLE_ServiceType.FIDO))
            if service_type != BLE_ServiceType.FIDO:
                continue
            return True
        return False

    def add_gatt_characteristic(self, characteristic_id, characteristic, value):
        if characteristic_id == BLE_Characteristic.u2fControlPoint:
            self.u2f_contol_point = characteristic
        elif characteristic_id == BLE_Characteristic.u2fStatus:
            self.u2f_status = characteristic
        else:
            super().add_gatt_characteristic(characteristic_id, characteristic, value)

    @property
    def u2f_frame_size(self):
        return int.from_bytes(self._characteristics[BLE_Characteristic.u2fControlPointLength],
                byteorder='big')

    async def write_frame(self, frame)
        self.write_gatt_char(self.u2f_control_point.uuid, frame)

    @property
    def u2f_service_revisions(self):
        return BLE_U2FServiceRevision(int.from_bytes(
            self._characteristics[BLE_Characteristic.u2fServiceRevisionBitfield], byteorder='big'))

    def __str__(self):
        strings = []
        strings.append('Manufacturer: %s' % self.manufacturer)
        strings.append('Model Number: %s' % self.model_number)
        strings.append('Firmware Rev: %s' % self.firmware_revision)
        strings.append('Battery Level: %d' % self.battery_level)
        strings.append('U2F Frame Size: %d' % self.u2f_frame_size)
        strings.append('U2F Service Revisions: %s' % self.u2f_service_revisions)
        return '\n'.join(strings)

class BLEFidoToken(FidoToken):
    def __init__(self, ble_device):
        self.ble_device = ble_device
        self.notification_data = []

    def notification_handler(self, sender, data):
        '''
        store the responses in a queue for read_frame() to
        read them
        '''
        print("{0}: {1}".format(sender, data))
        self.notification_data.append(append)

    async def write_frame(self, frame)
        await self.ble_device.write_frame(frame)

    async def read_frame(self, continuation=False):
        data = self.notification_data.pop(0)
        frame = self.frame_from_data(data, continuation)
        return frame

    async def request(self, request):
        await self.ble_device.start_notify(self.u2f_status.uuid, notification_handler)
        for frame in request.frames():
            await self.write_frame(frame)
        initial_response_frame = await self.read_frame()
        if not request._initialisation_frame.is_valid_response(initial_response_frame):
            raise Exception('invalid response %s' % initial_response_frame)
        response_frames = [initial_response_frame]
        if initial_response_frame._bytecount is None:
            payload_len = initial_response_frame.bytecount
            frame_count = continuation_frame_count(payload_len)
            for sequence in range(frame_count):
                continuation_response_frame = \
                    await self.read_frame(continuation=True)
                response_frames.append(continuation_response_frame)
        response = CTAPBLE_Response.from_frames(self, response_frames)
        await self.ble_device..stop_notify(self.u2f_status.uuid)

        return response

    def __str__(self):
        strings = [
            'Bluetooth Low Energy Fido Token',
            '     UUID: %s' % self.ble_device.uuid,
        ]
        return '\n'.join(strings)


async def run1(loop, debug=False):
    log = logging.getLogger(__name__)
    if debug:
        import sys

        loop.set_debug(True)
        log.setLevel(logging.DEBUG)
        h = logging.StreamHandler(sys.stdout)
        h.setLevel(logging.DEBUG)
        log.addHandler(h)

    devices = await discover()
    print('devices', len(devices))
    for d in devices:
        print('device', d)
        async with BLEFidoClient(d.address, loop=loop) as ble_client:
            x = await ble_client.is_connected()
            log.info("Connected: {0}".format(x))

            print(ble_client)
            if not ble_client.is_fido_device():
                continue
            await ble_client.get_gatt_config()
            print(ble_client)
            fido_token = BLEFidoToken(ble_client, ble_service)
            print(fido_token)
            break

async def run2(address, loop, debug=False):
    log = logging.getLogger(__name__)
    if debug:
        import sys

        loop.set_debug(True)
        log.setLevel(logging.DEBUG)
        h = logging.StreamHandler(sys.stdout)
        h.setLevel(logging.DEBUG)
        log.addHandler(h)
    async with BLEFidoClient(address, loop=loop) as client:
        x = await client.is_connected()
        log.info("Connected: {0}".format(x))
        if not client.is_fido_device():
            print('not a fido device')
            return
        await client.get_gatt_config()
        print(client)
        fido_token = BLEFidoToken(client)
        print(fido_token)
        

async def run3(address, loop, debug=False):
    log = logging.getLogger(__name__)
    if debug:
        import sys

        loop.set_debug(True)
        log.setLevel(logging.DEBUG)
        h = logging.StreamHandler(sys.stdout)
        h.setLevel(logging.DEBUG)
        log.addHandler(h)

    async with BleakClient(address, loop=loop) as client:
        x = await client.is_connected()
        log.info("Connected: {0}".format(x))

        for service in client.services:
            log.info("[Service] {0}: {1}".format(service.uuid, service.description))
            for char in service.characteristics:
                if "read" in char.properties:
                    try:
                        value = bytes(await client.read_gatt_char(char.uuid))
                    except Exception as e:
                        value = str(e).encode()
                else:
                    value = None
                log.info(
                    "\t[Characteristic] {0}: ({1}) | Name: {2}, Value: {3} ".format(
                        char.uuid, ",".join(char.properties), char.description, value
                    )
                )
                for descriptor in char.descriptors:
                    value = await client.read_gatt_descriptor(descriptor.handle)
                    log.info(
                        "\t\t[Descriptor] {0}: (Handle: {1}) | Value: {2} ".format(
                            descriptor.uuid, descriptor.handle, bytes(value)
                        )
                    )

loop = asyncio.get_event_loop()
#loop.run_until_complete(run1(loop, True))
loop.run_until_complete(run2(address, loop))
#loop.run_until_complete(run3(address, loop, True))


#from bleak import BleakClient
#address = "24:71:89:cc:09:05"
#MODEL_NBR_UUID = "00002a24-0000-1000-8000-00805f9b34fb"
#async def run(address, loop):
#async with BleakClient(address, loop=loop) as client:
#model_number = await client.read_gatt_char(MODEL_NBR_UUID)
#print("Model Number: {0}".format("".join(map(chr, model_number))))
#loop = asyncio.get_event_loop()
#loop.run_until_complete(run(address, loop))
