# standard python modules
import base64, os, re, secrets, sys
from hashlib import pbkdf2_hmac, sha256
from itertools import chain

#  python packages
import anyio
import asyncclick as click
from cryptography.fernet import Fernet

# local modules
from .ctap import CTAP_Command, CTAP_Request, CTAP_Response
from .hidtoken import hid_fido_tokens 
from .bletoken import ble_fido_tokens 
from .u2f import U2F_AuthControl, u2f_parse_signature
from .fidoclient import FidoClient

all_transports = ['BLE', 'NFC', 'USB']

@click.group(invoke_without_command=True)
@click.option('--transport', '-t', 'transports', multiple=True,
    type=click.Choice(all_transports, case_sensitive=False),
    help='search for tokens on the corrsponding transport(s)')
@click.option('--address', '-a', 'addresses', multiple=True,
    help='address of fido token')
@click.pass_context
async def cli(context, transports, addresses):
    token_chain = []
    if not transports:
        transports = all_transports
    for transport in transports:
        if transport == 'BLE':
            fido_tokens = ble_fido_tokens(addresses=addresses)
        #elif transport == 'NFC':
        #    token_chain.append(nfc_fido_tokens(addresse=addresses))
        elif transport == 'USB':
            fido_tokens = hid_fido_tokens(addresses=addresses)
        async for fido_token in fido_tokens:
            print(fido_token)
            if transport == 'USB':
                init_request = fido_token.ctap_request(CTAP_Command.INIT)
                init_response = await fido_token.request(init_request)
                print(init_response._initialization_frame)
                fido_token.channel_id = init_response._initialization_frame.new_channel_id

                # wink only available for USB
                wink_request = fido_token.ctap_request(CTAP_Command.WINK)
                wink_response = await fido_token.request(wink_request)
                print('wink response', wink_response._initialization_frame)

            ping_request = fido_token.ctap_request(CTAP_Command.PING,
                bytes(25*'deadbeef', encoding='ascii'))
            ping_response = await fido_token.request(ping_request)
            print('ping response', ping_response.payload)

            u2f_version = await fido_token.u2f_version()

            application = 'http://www.example.com'
            fido_client = FidoClient(fido_token, application)

            challenge = 'something wierd'
            u2f_response = await fido_client.u2f_register(challenge)
            await fido_client.u2f_authenticate(challenge, u2f_response.key_handle,
                control=U2F_AuthControl.DONT_ENFORCE_USER_PRESENCE_AND_SIGN)
            print('counter', fido_client.u2f_counter)

@cli.command(help='store a value of a key encrypted')
@click.pass_context
@click.argument('key')
@click.argument('value')
def put(context, key, value):
    fido_token = next(hid_fido_tokens())
    fido_token.initialize()
    application = 'fidolin:u2f-key-value-store'
    fido_client = FidoClient(fido_token, application)

    salt = os.urandom(32)
    iterations = 50000

    encrypted_value = fido_client.u2f_encrypt(key, value, salt, iterations)
        
    value_decrypted = fido_client.u2f_decrypt(key, encrypted_value, salt, iterations)
    print('value_decrypted', value_decrypted)


#@cli.command()
#def show(context):
#    "show found fido tokens"
#    click.echo('?')


def main():
    cli(_anyio_backend="asyncio")
    cli()

if __name__ == '__main__':
    sys.exit(main())
