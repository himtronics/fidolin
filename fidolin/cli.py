# standard python modules
import base64, os, re, secrets, sys
from hashlib import pbkdf2_hmac, sha256

#  python packages
from cryptography.fernet import Fernet
import click

# local modules
from .ctaphid import CTAPHID_Request, CTAPHID_Response, CTAPHID_Command
from .ctaphid import hid_fido_tokens 
from .u2f import U2F_AuthControl, u2f_parse_signature
from .fidoclient import FidoClient
from . import u2f_secret_storage

@click.group(invoke_without_command=True)
@click.option('--transport', '-t', multiple=True,
    type=click.Choice(['BLE', 'NFC', 'USB'], case_sensitive=False),
    help='search for tokens on the corrsponding transport(s)')
@click.option('--vendor_id', '-v')
@click.pass_context
def cli(context, transport, vendor_id):
    vendor_id = int(vendor_id) if vendor_id else None
    if False:
    #for fido_token in hid_fido_tokens(vendor_id=vendor_id):
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

        application = 'http://www.example.com'
        fido_client = FidoClient(application)

        challenge = 'something wierd'
        fido_client.u2f_register(fido_token, challenge)
        fido_client.u2f_authenticate(fido_token, challenge, control=U2F_AuthControl.DONT_ENFORCE_USER_PRESENCE_AND_SIGN)
        print('counter', fido_client.u2f_counter)

        # u2f secret storage
        application = 'example:u2f-secret-storage'
        fido_client = FidoClient(application)

        #challenge = os.urandom(32)
        fido_client.u2f_register(fido_token, challenge)

        password = 'geheim'
        salt = os.urandom(32)
        iterations = 50000
        
        key = pbkdf2_hmac('sha256', fido_client.public_key + password.encode('utf-8'), salt, iterations)
        print('secret', key.hex())
        #challenge = os.urandom(32)
        u2f_response = fido_client.u2f_authenticate(fido_token, challenge, control=U2F_AuthControl.DONT_ENFORCE_USER_PRESENCE_AND_SIGN)
        r,s = u2f_parse_signature(u2f_response.signature)
        print('r,s', r, s)

        message = u2f_response.message(challenge, application)
        public_keys = u2f_secret_storage.ecdsa.recover_candidate_pubkeys(
            u2f_secret_storage.ec.nistp256, sha256, message, (r, s))
        public_keys = [u2f_secret_storage.ec.nistp256.ec2osp(public_key)
            for public_key in public_keys]

        print('fido_client public_key', fido_client.public_key)
        print('public_keys', public_keys)
        for public_key in public_keys:
            print('public_key hash', sha256(public_key).digest())
            if public_key == fido_client.public_key:
                break
        else:
            raise Exception('no public key found')

        secret = pbkdf2_hmac('sha256', public_key + password.encode('utf-8'), salt, iterations)
        print('secret is', secret.hex())

        fido_token.close()

@cli.command(help='store a value of a key encrypted')
@click.pass_context
@click.argument('key')
@click.argument('value')
def put(context, key, value):
    fido_token = next(hid_fido_tokens())
    fido_token.initialize()
    application = 'example:u2f-secret-storage'
    fido_client = FidoClient(application)

    challenge = secrets.token_hex(32)
    fido_client.u2f_register(fido_token, challenge)

    salt = os.urandom(32)
    iterations = 50000
        
    secret = pbkdf2_hmac('sha256', fido_client.public_key + key.encode('utf-8'),
        salt, iterations)
    fernet = Fernet(base64.urlsafe_b64encode(secret))
    value_encrypted = fernet.encrypt(value.encode('utf-8'))
    data = {
        key: {
            'salt': salt,
            'value_encrypted': value_encrypted,
            'key_handle': fido_client.key_handle,
            'public_key_hash': sha256(fido_client.public_key).digest()
        }
    }

    application = 'example:u2f-secret-storage'
    challenge = secrets.token_hex(32)
    u2f_response = fido_client.u2f_authenticate(fido_token, challenge,
        control=U2F_AuthControl.DONT_ENFORCE_USER_PRESENCE_AND_SIGN)
    r,s = u2f_parse_signature(u2f_response.signature)

    message = u2f_response.message(challenge, application)
    public_keys = u2f_secret_storage.ecdsa.recover_candidate_pubkeys(
        u2f_secret_storage.ec.nistp256, sha256, message, (r, s))
    public_keys = [u2f_secret_storage.ec.nistp256.ec2osp(public_key)
        for public_key in public_keys]

    print('fido_client public_key', fido_client.public_key)
    print('public_keys', public_keys)
    print('data', data)
    for public_key in public_keys:
        public_key_hash = sha256(public_key).digest()
        if public_key_hash == data[key]['public_key_hash']:
             break
    else:
        raise Exception('no public key found')

    secret = pbkdf2_hmac('sha256', public_key + key.encode('utf-8'), salt, iterations)
    fernet = Fernet(base64.urlsafe_b64encode(secret))
    value_decrypted = fernet.decrypt(data[key]['value_encrypted']).decode('utf-8')
    print('value_decrypted', value_decrypted)


#@cli.command()
#def show(context):
#    "show found fido tokens"
#    click.echo('?')


def main():
    cli()

if __name__ == '__main__':
    sys.exit(main())
