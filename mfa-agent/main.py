#!/usr/bin/env python
#
# Author: Konrad Markus <konker@iki.fi>
#

import sys
import time
import math
import hashlib
import hmac
import base64
import socket
import daemon
import argparse
import toml
import getpass
import pykeepass

VERSION = '1.0.0'
DAEMON_GROUP_NAME = 'daemon'
PORT_KEY = 'port'
DATABASE_GROUP_NAME = 'database'
DATABASE_FILE_KEY = 'kdbx_database_file'
KEY_FILE_KEY = 'kdbx_key_file'
DEFAULT_PORT = 987654


# Quick way to generate Google Authenticator tokens widely used for multi-factor authentication
# Requires the shared secret to be made available:
# either through stdin or by specifiying a file which contains the secret as an argument
# Prints the current code to stdout
#
# Basically a direct translation of the Wikipedia pseudo-code into Python3
#
#  From wikipedia:
#  https://en.wikipedia.org/wiki/Google_Authenticator#Pseudocode_for_Event.2FCounter_OTP
#
#  function GoogleAuthenticatorCode(string secret)
#      key := base32decode(secret)
#      message := floor(current Unix time / 30)
#      hash := HMAC-SHA1(key, message)
#      offset := last nibble of hash
#      truncatedHash := hash[offset..offset+3]  //4 bytes starting at the offset
#      Set the first bit of truncatedHash to zero  //remove the most significant bit
#      code := truncatedHash mod 1000000
#      pad code with 0 until length of code is 6
#      return code
#
def totp(secret):
    # key := base32decode(secret)
    key = base64.b32decode(secret)

    # message := floor(current Unix time / 30)
    message = math.floor(time.time() / 30).to_bytes(8, 'big')

    # hash := HMAC-SHA1(key, message)
    hash = bytearray(hmac.new(key, message, hashlib.sha1).digest())

    # offset := last nibble of hash
    offset = int.from_bytes([hash[-1]], 'big') & 0x0F

    # truncatedHash := hash[offset..offset+3]  //4 bytes starting at the offset
    truncated_hash = hash[offset:offset + 4]

    # Set the first bit of truncatedHash to zero  //remove the most significant bit
    truncated_hash[0] = (int.from_bytes([truncated_hash[0]], 'big') & 0x7F)

    # code := truncatedHash mod 1000000
    code = int.from_bytes(truncated_hash, 'big') % 1000000

    # pad code with 0 until length of code is 6
    return '{0:06d}'.format(code)


def sanitize(s):
    return s.decode('utf-8').strip().upper()


def handle_data(secrets, data):
    sanitized = sanitize(data)
    if sanitized == 'HELO':
        return f'mfa-agent: {VERSION}'
    if sanitized == 'LIST':
        return '\n'.join(secrets.keys())
    elif sanitized == 'EXIT':
        return 'EXIT'
    elif sanitized in secrets:
        return totp(secrets[sanitized])
    else:
        return 'UNKNOWN'


def serve_forever(secrets, port=DEFAULT_PORT):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('', port))
    server.listen(1)
    while True:
        conn, address = server.accept()
        data = conn.recv(1024)
        response = handle_data(secrets, data)
        conn.send(response.encode('utf-8'))
        conn.close()

        if response == 'EXIT':
            return


def main():
    # read in command line args
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind-address", "-b", help="Port to bind to", default=DEFAULT_PORT)
    parser.add_argument("--config", "-c", help="Path to the config file")
    args = parser.parse_args()

    if not args.config:
        print('[mfa-agent] STDERR, No config file specified')
        sys.exit(-1)

    # Load config
    print('[mfa-agent] Loading config:', args.config)
    config = toml.load(args.config)

    if not config[DATABASE_GROUP_NAME] or not config[DAEMON_GROUP_NAME]:
        print('[mfa-agent] STDERR, Bad config')
        sys.exit(1)

    if not config[DAEMON_GROUP_NAME][PORT_KEY]:
        print(f'[mfa-agent] STDERR, No {PORT_KEY} specified in config')
        sys.exit(1)

    if not config[DATABASE_GROUP_NAME][DATABASE_FILE_KEY]:
        print(f'[mfa-agent] STDERR, No {DATABASE_FILE_KEY} specified in config')
        sys.exit(1)

    kdbx_database_file = config[DATABASE_GROUP_NAME][DATABASE_FILE_KEY]
    kdbx_key_file = config[DATABASE_GROUP_NAME][KEY_FILE_KEY]

    print(f'[mfa-agent] Loading database file: {kdbx_database_file}')
    if kdbx_key_file:
        print(f'[mfa-agent] Using keyfile: {kdbx_key_file}')

    # Read in password
    password = getpass.getpass(prompt='[mfa-agent] Enter password: ')

    # Load in database
    kp = pykeepass.PyKeePass(kdbx_database_file, password=password, keyfile=kdbx_key_file)

    # Get group(s) from config
    group_names = [k for k in config.keys() if k != DATABASE_GROUP_NAME and k != DAEMON_GROUP_NAME]

    secrets = {}

    # Load the entries from each group into memory
    for group_name in group_names:
        if 'entries' not in config[group_name]:
            print(f'[mfa-agent] STDERR, No entries in group: {group_name}, skipping')
            continue

        entry_names = config[group_name]['entries']

        for entry_name in entry_names:
            entry_path = f'{group_name}/{entry_name}'
            entry = kp.find_entries(path=entry_path, recursive=True, first=True)

            if entry:
                secrets[entry_name.upper()] = entry.password
            else:
                print(f'[mfa-agent] STDERR, Could not find entry: {entry_path}')

    port = config[DAEMON_GROUP_NAME][PORT_KEY]

    # TODO: spawn daemon to listen to socket requests and give secrets
    with daemon.DaemonContext():
        serve_forever(secrets, port)


if __name__ == '__main__':
    main()
