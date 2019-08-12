#!/usr/bin/env python

import sys
import argparse
import toml
import getpass
import pykeepass


DATABASE_GROUP_NAME = 'database'
DATABASE_FILE_KEY = 'kdbx_database_file'
KEY_FILE_KEY = 'kdbx_key_file'

DATA = {}


def main():
    # read in command line args
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", help="Path to the config file")
    args = parser.parse_args()

    if not args.config:
        print('[mfa-agent] STDERR, No config file specified')
        sys.exit(-1)

    # Load config
    print('[mfa-agent] Loading config:', args.config)
    config = toml.load(args.config)

    if not config[DATABASE_GROUP_NAME]:
        print('[mfa-agent] STDERR, Bad config')
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
    group_names = [k for k in config.keys() if k != DATABASE_GROUP_NAME]

    # Load the entries from each group into memory
    for group_name in group_names:
        entry_names = config[group_name]['entries']

        for entry_name in entry_names:
            entry_path = f'{group_name}/{entry_name}'
            entry = kp.find_entries(path=entry_path, recursive=True, first=True)

            if entry:
                DATA[entry_name] = entry.password
            else:
                print(f'[mfa-agent] STDERR, Could not find entry: {entry_path}')

    # TODO: spawn daemon to listen to socket requests and give secrets
    print('KONK95', DATA)


if __name__ == '__main__':
    main()
