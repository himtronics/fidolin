import os, re, sys

from .ctaphid import CTAPHID_Request, CTAPHID_Response, CTAPHID_Command
from .ctaphid import hid_fido_tokens 
from .u2f import U2F_Request, U2F_Response, U2F_Command
import click

@click.group(invoke_without_command=True)
@click.option('--transport', '-t', multiple=True,
    type=click.Choice(['BLE', 'NFC', 'USB'], case_sensitive=False),
    help='search for tokens on the corrsponding transport(s)')
@click.pass_context
def cli(context, transport):
    for fido_token in hid_fido_tokens():
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
            bytes(20*'abcde', encoding='ascii'))
        ping_response = fido_token.request(ping_request)
        print('ping response', ping_response.payload)

        u2f_version_request = U2F_Request(ins=U2F_Command.VERSION)
        print('u2f_version_request', u2f_version_request)
        msg_request = CTAPHID_Request(fido_token, CTAPHID_Command.MSG,
            u2f_version_request)
        msg_response = fido_token.request(msg_request)
        u2f_version_response = U2F_Response(msg_response.payload)
        u2f_version_response.check_sw()
        print('msg response', u2f_version_response.data)
        fido_token.close()

#@cli.command()
#def show(context):
#    "show found fido tokens"
#    click.echo('?')


def main():
    cli()

if __name__ == '__main__':
    sys.exit(main())
