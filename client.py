#!/usr/bin/env python
"""Basic commandline tool for interacting with hagrid."""
import argparse
import base64
import requests
import sys
import json

from os.path import expanduser

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def parse_key(key):
    return serialization.load_ssh_public_key(
        key,
        backend=default_backend()
    )


def stringify_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )


def encrypt(public_key, message):
    cipher = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher


def decrypt(private_key, ciphertext):
    plain = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plain


def sign(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verbose_to_prefix(verbosity):
    lookup_table = {
       -1: '',
        0: 'ERROR',
        1: 'WARNING',
        2: 'INFO',
        3: 'DEBUG',
        4: 'SPAM',
    }
    return lookup_table[verbosity]


def verbose_print(args, verbosity, message):
    """Print message, if verbosity is over args.verbose."""
    if args.verbose >= verbosity:
        print verbose_to_prefix(verbosity) + ": " + message


def load_private_key(path, password):
    """Load the private key from 'path', unlock with 'password'."""
    # Expand '~' to absolute path
    user_path = expanduser(path)
    # Load key using password
    with open(user_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key


def list_passwords(args):
    response = requests.get(
        'http://' + args.url + '/api/keyentry/',
        auth=(args.username, args.password)
    )
    # TODO: Pull all via 'next'
    results = response.json()['results']
    if len(results) != 0:
        print "Passwords:"
        for key_entry in results:
            print "* " + str(key_entry['pk']) + ": " + key_entry['title']
    else:
        print "No passwords found!"


def get_password(args, my_private_key, my_public_key, key_entry_pk):
    response = requests.get(
        'http://' + args.url + '/api/keyentry/',
        auth=(args.username, args.password)
    )
    # TODO: Pull all via 'next'
    results = response.json()['results']
    if len(results) == 0:
        print "Unable to lookup password!"
        return

    key_entries = list_dict_search("pk", key_entry_pk, results)
    if len(key_entries) != 1:
        print "Unable to lookup password!"
        return

    key_entry = key_entries[0]
    my_public_key_pk = get_public_key_pk(args, my_public_key)
    passwords = [x for x in key_entry['passwords'] if x['public_key']['pk'] == my_public_key_pk]
    if len(passwords) != 1:
        print "Database invariant broken!"
        return

    # We have the password object, and thus the password
    password = passwords[0]
    incoming_encoded_password = password['password']
    incoming_encrypted_password = base64.b64decode(incoming_encoded_password)
    incoming_password = decrypt(my_private_key, incoming_encrypted_password)

    # Print information to the user
    print "Found password:"
    print "- " + "title: " + key_entry['title']
    print "- " + "url: " + key_entry['url']
    print "- " + "notes: " + key_entry['notes']
    print "- " + "username: " + key_entry['username']
    print "- " + "password: " + incoming_password


def get_public_key_pk(args, my_public_key):
    verbose_print(args, 3, "Finding our own user pk")
    response = requests.get(
        'http://' + args.url + '/api/user/',
        auth=(args.username, args.password)
    )
    # TODO: Pull all via 'next'
    # TODO: Lookup using filter
    results = response.json()['results']
    # Find personal group via name
    user_dict = list_dict_search("username", args.username, results)[0]
    user_pk = user_dict['pk']
    verbose_print(args, 3, "Found our own user pk: " + str(user_pk))

    # Gather all public keys related to the group
    verbose_print(args, 3, "Finding our own public key pk")
    response = requests.get(
        'http://' + args.url + '/api/public_key/',
        auth=(args.username, args.password)
    )
    # TODO: Pull all via 'next'
    # TODO: Lookup using filter
    results = response.json()['results']
    # TODO: This only works if database keys has no comments (fix or strip database comments)
    user_keys = list_dict_search("user", user_pk, results)
    my_public_key_string = stringify_public_key(my_public_key)
    my_public_key_pk = list_dict_search("key", my_public_key_string, user_keys)[0]['pk']
    verbose_print(args, 3, "Found our own public key pk: " + str(my_public_key_pk))
    return my_public_key_pk


def list_dict_search(key, value, list_of_dicts):
    return [element for element in list_of_dicts if element[key] == value]


def store_password(args, my_private_key, my_public_key, store_dict):
    verbose_print(args, 3, "Finding group users")
    response = requests.get(
        'http://' + args.url + '/api/group/',
        auth=(args.username, args.password)
    )
    # TODO: Pull all via 'next'
    # TODO: Lookup using filter
    results = response.json()['results']
    # Find personal group via name
    group_dict = list_dict_search("name", args.username, results)[0]
    group_pk = group_dict['pk']
    users = [user['pk'] for user in group_dict['user_set']]
    # Always include master user
    users.append(1)
    verbose_print(args, 3, "Found users: " + str(users))


    # Gather all public keys related to the group
    verbose_print(args, 3, "Gathering public keys")
    response = requests.get(
        'http://' + args.url + '/api/public_key/',
        auth=(args.username, args.password)
    )
    # TODO: Pull all via 'next'
    # TODO: Lookup using filter
    results = response.json()['results']
    public_keys = [public_key for public_key in results if public_key['user'] in users]
    verbose_print(args, 3, "Found public keys: " + str([x['pk'] for x in public_keys]))
    # Pull out the signing key
    signing_key_pk = get_public_key_pk(args, my_public_key)

    # The password we are actually saving
    if 'password' not in store_dict:
        verbose_print(args, 0, "password not provided!")
        return
    password = str(store_dict['password'])

    # Prepare the passwords write object
    passwords_write = []
    for public_key in public_keys:
        # Parse the public key into a crypotgraphy object
        key_object = parse_key(public_key['key'])
        # Encrypt, sign and base64 encode
        encrypted_password = encrypt(key_object, password)
        signature = sign(my_private_key, encrypted_password)
        encoded_password = base64.b64encode(encrypted_password)
        encoded_signature = base64.b64encode(signature)

        verbose_print(args, 4, "Encoded Password: " + encoded_password)
        verbose_print(args, 4, "Encoded Signature: " + encoded_signature)

        passwords_write.append({
            'key_pk': public_key['pk'],
            'password': encoded_password,
            'signature': encoded_signature,
        })

    def load_or_blank(key):
        if key in store_dict:
            return store_dict[key]
        return ""

    # Prepare our payload object
    payload = {
        "owner": group_pk,
        "url": load_or_blank('url'),
        "passwords_write": passwords_write,
        "title": load_or_blank('title'),
        "username": load_or_blank('username'),
        "notes": load_or_blank('notes'),
        "signing_key": signing_key_pk,
    }
    response = requests.post(
        'http://' + args.url + '/api/keyentry/',
        auth=(args.username, args.password),
        json=payload
    )
    print response
    print response.text


def main():
    """Populate db according to arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-l', '--list-passwords',
        help='List all passwords associated to the user.',
        action='store_true',
        default=False
    )
    parser.add_argument(
        '-g', '--get-password',
        help='Get a password by providing its primary key.',
        action='store',
        type=int,
        default=None
    )
    parser.add_argument(
        '-s', '--store-password',
        help='Store a password by providing a json object.',
        action='store',
        default=None
    )
    parser.add_argument(
        '-a', '--url',
        help='The url of the server.',
        action='store',
        default='localhost:8000'
    )
    parser.add_argument(
        '-u', '--username',
        help='The username used to log into the server.',
        action='store',
        default=None
    )
    parser.add_argument(
        '-p', '--password',
        help='The password used to log into the server.',
        action='store',
        default=None
    )
    parser.add_argument(
        '-k', '--private-key',
        help='Path to the private key to use.',
        action='store',
        default='~/.ssh/id_rsa'
    )
    parser.add_argument(
        '-i', '--private-key-password',
        help='Password to unlock private key (if required).',
        action='store',
        default=None
    )
    parser.add_argument(
        '-v', '--verbose',
        help='Verbosity of the output.',
        action='count',
        default=0
    )
    args = parser.parse_args()

    if args.username is None:
        verbose_print(args, 0, "Username must be provided!")
        sys.exit(1)

    if args.password is None:
        verbose_print(args, 0, "Password must be provided!")
        sys.exit(1)

    if args.verbose > 4:
        verbose_print(args, 1, "Verbosity limited can max be 4")

    verbose_print(args, 3, "Commandline arguments: " + str(args))

    verbose_print(args, 2, "Loading private key from: " + args.private_key)

    private_key, public_key = load_private_key(
        path=args.private_key,
        password=args.private_key_password
    )

    verbose_print(args, 3, "Private key loading successful")

    if args.list_passwords:
        list_passwords(args)

    if args.store_password is not None:
        store_dict = json.loads(args.store_password)
        store_password(args, private_key, public_key, store_dict)

    if args.get_password is not None:
        # Parse get_password into python dict
        get_password(args, private_key, public_key, args.get_password)

if __name__ == "__main__":
    main()
