# standard python modules
import base64, os, re, secrets, sys
from hashlib import pbkdf2_hmac, sha256
from itertools import chain

#  python packages
from cryptography.fernet import Fernet
import click

# local modules
from .ctap import CTAP_Command
from .ctaphid import CTAPHID_Request, CTAPHID_Response
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
def cli(context, transports, addresses):
    token_chain = []
    if not transports:
        transports = all_transports
    for transport in transports:
        if transport == 'BLE':
            token_chain.append(ble_fido_tokens(addresse=addresses))
        #elif transport == 'NFC':
        #    token_chain.append(nfc_fido_tokens(addresse=addresses))
        elif transport == 'USB':
            token_chain.append(hid_fido_tokens(addresse=addresses))
    for fido_token in chain(*token_chain):
        print(fido_token)
        init_request = CTAPHID_Request(fido_token, CTAP_Command.INIT)
        init_response = fido_token.request(init_request)
        print(init_response._initialization_frame)
        #if not init_request_frame.is_valid_response(init_response_frame):
        #    fido_token.hid_device.close()
        #    continue
        fido_token.channel_id = init_response._initialization_frame.new_channel_id

        wink_request = CTAPHID_Request(fido_token, CTAP_Command.WINK)
        wink_response = fido_token.request(wink_request)
        print('wink response', wink_response._initialization_frame)

        ping_request = CTAPHID_Request(fido_token, CTAP_Command.PING,
            bytes(25*'deadbeef', encoding='ascii'))
        ping_response = fido_token.request(ping_request)
        print('ping response', ping_response.payload)

        u2f_version = fido_token.u2f_version()

        application = 'http://www.example.com'
        fido_client = FidoClient(fido_token, application)

        challenge = 'something wierd'
        u2f_response = fido_client.u2f_register(challenge)
        fido_client.u2f_authenticate(challenge, u2f_response.key_handle,
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
    cli()

if __name__ == '__main__':
    sys.exit(main())
