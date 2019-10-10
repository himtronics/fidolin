import os, re, sys

from .ctaphid import CTAPHID_Request, CTAPHID_Response, CTAPHID_Command
from .ctaphid import hid_fido_tokens 
from .u2f import U2F_AuthControl
import click

@click.group(invoke_without_command=True)
@click.option('--transport', '-t', multiple=True,
    type=click.Choice(['BLE', 'NFC', 'USB'], case_sensitive=False),
    help='search for tokens on the corrsponding transport(s)')
@click.option('--vendor_id', '-v')
@click.pass_context
def cli(context, transport, vendor_id):
    vendor_id = int(vendor_id) if vendor_id else None
    for fido_token in hid_fido_tokens(vendor_id=vendor_id):
        print(fido_token)
        init_request = CTAPHID_Request(fido_token, CTAPHID_Command.INIT)
        init_response = fido_token.request(init_request)
        print(init_response._initialisation_packet)
        #if not init_request_packet.is_valid_response(init_response_packet):
        #    fido_token.hid_device.close()
        #    continue
        fido_token.channel_id = init_response._initialisation_packet.new_channel_id

        wink_request = CTAPHID_Request(fido_token, CTAPHID_Command.WINK)
        wink_response = fido_token.request(wink_request)
        print('wink response', wink_response._initialisation_packet)

        ping_request = CTAPHID_Request(fido_token, CTAPHID_Command.PING,
            bytes(25*'deadbeef', encoding='ascii'))
        ping_response = fido_token.request(ping_request)
        print('ping response', ping_response.payload)

        u2f_version = fido_token.u2f_version()
        challenge = 'something wierd'
        application = 'http://www.emesgarten.de'
        u2f_register = fido_token.u2f_register(challenge, application)
        public_key = u2f_register.public_key
        key_handle = u2f_register.key_handle
        u2f_response = fido_token.u2f_authenticate(challenge, application,
            key_handle, control=U2F_AuthControl.DONT_ENFORCE_USER_PRESENCE_AND_SIGN)
        print('u2f_authenticate', u2f_response)
        u2f_response.verify_signature(challenge, application, public_key)
        print('counter', u2f_response.counter)
        fido_token.close()

#@cli.command()
#def show(context):
#    "show found fido tokens"
#    click.echo('?')


def main():
    cli()

if __name__ == '__main__':
    sys.exit(main())
