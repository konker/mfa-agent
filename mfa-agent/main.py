#!/usr/bin/env python
#
# Author: Konrad Markus <konker@iki.fi>
#

import os
import sys
import time
import math
import hashlib
import hmac
import base64
import socket
import signal
import daemon
import argparse
import toml
import getpass
import pykeepass

VERSION = '1.0.0'
DAEMON_GROUP_NAME = 'daemon'
DATABASE_GROUP_NAME = 'database'
DATABASE_FILE_KEY = 'kdbx_database_file'
KEY_FILE_KEY = 'kdbx_key_file'
DEFAULT_SOCKET_PATH = '/tmp/mfa-agent-sock'

HELLO_COMMAND = 'hello'
LIST_COMMAND = 'list'
EXIT_COMMAND = 'exit'
LOAD_COMMAND = 'load'
COMMANDS = [HELLO_COMMAND, LIST_COMMAND, EXIT_COMMAND, LOAD_COMMAND]

running = False

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
    return s.decode('utf-8').strip().lower()


def vstring():
    return f'mfa-agent: {VERSION}'


def handle_data(secrets, data):
    sanitized = sanitize(data)
    if sanitized == HELLO_COMMAND:
        return vstring()
    if sanitized == LIST_COMMAND:
        return '\n'.join(secrets.keys())
    elif sanitized == EXIT_COMMAND:
        return 'EXIT'
    elif sanitized in secrets:
        return totp(secrets[sanitized])
    else:
        return 'UNKNOWN'


def shutdown(signum, frame):
    global running
    running = False


def serve_forever(secrets, socket_path):
    global running

    if os.path.exists(socket_path):
        os.remove(socket_path)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(1)
    running = True

    while running:
        conn, address = server.accept()
        data = conn.recv(1024)
        response = handle_data(secrets, data)
        conn.send(response.encode('utf-8'))
        conn.close()

        if response == 'EXIT':
            shutdown(None, None)


def load_agent(args):
    # Load config
    print('[mfa-agent] Loading config:', args.config)
    config = toml.load(args.config)

    if not config.get(DATABASE_GROUP_NAME):
        print(f'[mfa-agent] STDERR, Bad config, no {DATABASE_GROUP_NAME} group', file=sys.stderr)
        sys.exit(1)

    if not config.get(DATABASE_GROUP_NAME, {}).get(DATABASE_FILE_KEY):
        print(f'[mfa-agent] STDERR, No {DATABASE_FILE_KEY} specified in config', file=sys.stderr)
        sys.exit(1)

    kdbx_database_file = config[DATABASE_GROUP_NAME][DATABASE_FILE_KEY]
    kdbx_key_file = config[DATABASE_GROUP_NAME][KEY_FILE_KEY]

    print(f'[mfa-agent] Loading database file: {kdbx_database_file}')
    if kdbx_key_file:
        print(f'[mfa-agent] Using keyfile: {kdbx_key_file}')

    # Read in password
    password = getpass.getpass(prompt='[mfa-agent] Enter password: ')

    # Load in database
    try:
        kp = pykeepass.PyKeePass(kdbx_database_file, password=password, keyfile=kdbx_key_file)
    except(ValueError, Exception):
        print('[mfa-agent] STDERR, FATAL ERROR: Could not open database')
        sys.exit(1)

    # Get group(s) from config
    group_names = [k for k in config.keys() if k != DATABASE_GROUP_NAME and k != DAEMON_GROUP_NAME]

    secrets = {}

    # Load the entries from each group into memory
    for group_name in group_names:
        if 'entries' not in config[group_name]:
            print(f'[mfa-agent] STDERR, No entries in group: {group_name}, skipping', file=sys.stderr)
            continue

        entry_names = config[group_name]['entries']

        if entry_names == "all":
            group = kp.find_groups(name=group_name, first=True)
            if group:
                entry_names = [i.title for i in group.entries]
            else:
                print(f'[mfa-agent] STDERR, Warning: Could not find group: {group_name}', file=sys.stderr)
                entry_names = []

        for entry_name in entry_names:
            if entry_name.lower() in COMMANDS:
                print(f'[mfa-agent] STDERR, Ignoring entry with reserved name: {entry_name}', file=sys.stderr)
                continue

            entry_path = f'{group_name}/{entry_name}'
            entry = kp.find_entries(path=entry_path, recursive=True, first=True)

            if entry:
                secrets[entry_name.lower()] = entry.password
            else:
                print(f'[mfa-agent] STDERR, Could not find entry: {entry_path}', file=sys.stderr)

    # Spawn daemon to listen to socket requests and give codes
    print(f'[mfa-agent] Spawning daemon on socket: {args.socket_path}')
    with daemon.DaemonContext(signal_map={
        signal.SIGTERM: shutdown,
        signal.SIGTSTP: shutdown
    }):
        serve_forever(secrets, args.socket_path)


def query_agent(name, socket_path, bufsize):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(socket_path)
    sock.send(name.encode('utf-8'))
    return sock.recv(bufsize).decode('utf-8')


def query_code(name, socket_path):
    print(f'[mfa-agent] STDERR, query code {name} on socket {socket_path}', file=sys.stderr)
    return query_agent(name, socket_path, 6)


def query_command(name, socket_path):
    print(f'[mfa-agent] STDERR, query command {name} on socket {socket_path}', file=sys.stderr)
    return query_agent(name, socket_path, 2024)


def check_running(socket_path):
    try:
        response = query_command(HELLO_COMMAND, socket_path)
        return response == vstring()
    except (FileNotFoundError, ConnectionRefusedError):
        return False


def main():
    # read in command line args
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket-path", "-b", help="Unix socket path to use", default=DEFAULT_SOCKET_PATH)
    parser.add_argument("--config", "-c", help="Path to the config file")
    parser.add_argument("command", help=f"`{LOAD_COMMAND}` to start agent, or entry name to query")
    args = parser.parse_args()

    if not args.command:
        print('[mfa-agent] STDERR, No command specified', file=sys.stderr)
        sys.exit(-1)

    if args.command.lower() == LOAD_COMMAND:
        if not args.config:
            print('[mfa-agent] STDERR, No config file specified for load command', file=sys.stderr)
            sys.exit(-2)

        if check_running(args.socket_path):
            print(f'[mfa-agent] STDERR, Already running on socket {args.socket_path}', file=sys.stderr)
        else:
            load_agent(args)

    elif args.command.lower() in COMMANDS:
        try:
            print(query_command(args.command, args.socket_path))
        except (FileNotFoundError, ConnectionRefusedError):
            print(f'[mfa-agent] STDERR, Agent not running on socket {args.socket_path}', file=sys.stderr)

    else:
        try:
            print(query_code(args.command, args.socket_path))
        except (FileNotFoundError, ConnectionRefusedError):
            print(f'[mfa-agent] STDERR, Agent not running on socket {args.socket_path}', file=sys.stderr)


if __name__ == '__main__':
    main()
