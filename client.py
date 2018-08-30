#!/usr/bin/env python
"""Basic commandline tool for interacting with hagrid."""
import argparse
import base64
import requests
import sys
import json
import logging
logger = logging.getLogger('hagrid-client')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

from os.path import expanduser

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def username_to_pk(args, username, return_dict=False):
    """Translate a username into a primary key."""
    response = requests.get(
        'http://' + args.url + '/api/user/?username=' + username,
        auth=(args.username, args.password)
    )
    if response.status_code == 403:
        logger.error("Bad authentification information.")
        return

    if response.status_code != 200:
        logger.error("Non 200 return code.")
        return
    
    json = response.json()
    if json['count'] == 0:
        logger.info("No such user found.")
        return
    elif json['count'] > 1:
        logger.error("Multiple users found, invariant broken!")
        return

    user_dict = json['results'][0]
    if return_dict:
        return user_dict
    return user_dict['pk']


def groupname_to_pk(args, groupname, return_dict=False):
    response = requests.get(
        'http://' + args.url + '/api/group/?name=' + groupname,
        auth=(args.username, args.password)
    )
    if response.status_code == 403:
        logger.error("Bad authentification information.")
        return

    if response.status_code != 200:
        logger.error("Non 200 return code.")
        return

    json = response.json()
    if json['count'] == 0:
        logger.info("No groups found.")
        return
    elif json['count'] > 1:
        logger.error("Multiple groups found, invariant broken!")
        return

    # Prepare group
    group_dict = json['results'][0]
    if return_dict:
        return group_dict
    return group_dict['pk']




def create_user(args, public_key):
    """Create a new user."""
    payload = {
        'username': args.username,
        'password': args.password,
        'public_key': stringify_public_key(public_key),
    }
    response = requests.post(
        'http://' + args.url + '/api/user/',
        json=payload
    )
    if response.status_code == 403:
        logger.error("Bad authentification information.")
        return

    if response.status_code != 201:
        logger.error("Non 201 return code.")
        return

    json = response.json()
    if 'pk' in json:
        logger.info("User created!")
        return json['pk']


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


def create_group(args):
    """Create a new group."""
    if args.group is None:
        logger.error("No group provided!")
        return

    payload = {
        'name': args.group,
    }
    response = requests.post(
        'http://' + args.url + '/api/group/',
        json=payload,
        auth=(args.username, args.password)
    )
    if response.status_code == 403:
        logger.error("Bad authentification information.")
        return

    if response.status_code != 201:
        logger.error("Non 201 return code.")
        return

    json = response.json()
    if 'pk' in json:
        logger.info("Group created!")
        return json['pk']


def associate_user(args):
    """Create a new group."""
    if args.group is None:
        logger.error("No group provided!")
        return
    if args.associate_user is None:
        logger.error("No associate username provided!")
        return

    group_pk = groupname_to_pk(args, args.group)
    if group_pk is None:
        return

    associate_user_pk = username_to_pk(args, args.associate_user)
    if associate_user_pk is None:
        return

    payload = {
        'user_pk': associate_user_pk,
    }
    response = requests.patch(
        'http://' + args.url + '/api/group_associate/' + str(group_pk) + "/",
        json=payload,
        auth=(args.username, args.password)
    )
    if response.status_code == 403:
        logger.error("Bad authentification information.")
        return

    if response.status_code != 200:
        logger.error("Non 200 return code.")
        return

    json = response.json()
    if 'pk' in json:
        logger.info("Group association created!")
        return json['pk']


def accumulate(itr, func, initial=0):
    accum = initial
    for item in itr:
        func(accum, item)
    return accum


def download_all_as_list(args, response):
    json = response.json()
    listy = json['results']
    while json['next'] is not None:
        response = requests.get(
            json['next'],
            auth=(args.username, args.password)
        )
        json = response.json()
        listy.extend(json['results'])
    return listy


def list_groups(args):
    """List all groups visible to the current user."""
    response = requests.get(
        'http://' + args.url + '/api/group/',
        auth=(args.username, args.password)
    )
    if response.status_code == 403:
        logger.error("Bad authentification information.")
        return

    if response.status_code != 200:
        logger.error("Non 200 return code.")
        return
    
    groups = download_all_as_list(args, response)
    print "Groups:"
    
    for group in groups:
        group_name = group['name']
        print "* " + group_name


def list_passwords(args):
    """List all passwords visible to the current user."""
    response = requests.get(
        'http://' + args.url + '/api/keyentry/',
        auth=(args.username, args.password)
    )
    if response.status_code == 403:
        logger.error("Bad authentification information.")
        return

    if response.status_code != 200:
        logger.error("Non 200 return code.")
        return

    passwords = download_all_as_list(args, response)

    if len(passwords) != 0:
        print "Passwords:"
        
        def grouper(acc, elem):
            group_name = elem['owner']['name']
            if group_name not in acc:
                acc[group_name] = []
            acc[group_name].append({'pk': elem['pk'], 'title': elem['title']})

        grouped = accumulate(passwords, grouper, {})
        for group_name, entries in grouped.iteritems():
            print "|"
            print "| " + group_name + ":"
            # entries = sorted(entries, key=lambda x: int(x['pk']))
            for entry in entries:
                print "|--- " + str(entry['pk']) + ": " + entry['title']
    else:
        print "No passwords found!"


def get_password(args, my_private_key, my_public_key, key_entry_pk):
    """Retrieve a password from the database using an ID."""
    my_public_key_pk = get_public_key_pk(args, my_public_key)

    response = requests.get(
        'http://' + args.url + '/api/password/?public_key=' + str(my_public_key_pk) + "&key_entry=" + str(key_entry_pk),
        auth=(args.username, args.password)
    )
    if response.status_code == 403:
        logger.error("Bad authentification information.")
        return

    if response.status_code != 200:
        logger.error("Non 200 return code.")
        return

    json = response.json()
    if json['count'] == 0:
        logger.info("No such password found.")
        return
    elif json['count'] > 1:
        logger.error("Multiple passwords found, invariant broken!")
        return

    # We have the password object, and thus the password
    password = json['results'][0]
    incoming_encoded_password = password['password']
    incoming_encrypted_password = base64.b64decode(incoming_encoded_password)
    incoming_password = decrypt(my_private_key, incoming_encrypted_password)

    # Print information to the user
    print "Found password: '" + incoming_password + "'"


def get_public_key_pk(args, my_public_key):
    """Get our public key pk of the current key."""
    user_pk = username_to_pk(args, args.username)
    logger.debug("Found our own user pk: " + str(user_pk))

    response = requests.get(
        'http://' + args.url + '/api/public_key/?user=' + str(user_pk),
        auth=(args.username, args.password)
    )
    if response.status_code == 403:
        logger.error("Bad authentification information.")
        return

    if response.status_code != 200:
        logger.error("Non 200 return code.")
        return

    public_keys = download_all_as_list(args, response)

    # TODO: This only works if public keys are stripped of comments
    my_public_key_string = stringify_public_key(my_public_key)
    my_public_key_pk = list_dict_search("key", my_public_key_string, public_keys)[0]['pk']

    logger.debug("Found our own public key pk: " + str(my_public_key_pk))
    return my_public_key_pk


def list_dict_search(key, value, list_of_dicts):
    return [element for element in list_of_dicts if element[key] == value]


def store_password(args, my_private_key, my_public_key, store_dict):
    """Store a password on the server."""
    # The password we are actually saving
    if 'password' not in store_dict:
        logger.error("Password not provided!")
        return
    password = str(store_dict['password'])

    group_name = args.group or args.username
    # Prepare group
    group_dict = groupname_to_pk(args, group_name, return_dict=True)
    if group_dict is None:
        return
    group_pk = group_dict['pk']
    users = [user['pk'] for user in group_dict['user_set']]
    # Always include master user
    users.append(1)
    logger.debug("Found users: " + str(users))

    # Pull out the signing key
    signing_key_pk = get_public_key_pk(args, my_public_key)

    # Gather all public keys related to the group
    # TODO: Lookup using filter (user__in=users, or user__group=group_pk)
    response = requests.get(
        'http://' + args.url + '/api/public_key/',
        auth=(args.username, args.password)
    )
    results = download_all_as_list(args, response)
    public_keys = [public_key for public_key in results if public_key['user'] in users]
    logger.debug("Found public keys: " + str([x['pk'] for x in public_keys]))

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

        logger.debug("Encoded Password: " + encoded_password)
        logger.debug("Encoded Signature: " + encoded_signature)

        passwords_write.append({
            'key_pk': public_key['pk'],
            'password': encoded_password,
            'signature': encoded_signature,
        })

    load_or_blank = lambda key: store_dict[key] if key in store_dict else ""

    # Prepare our payload object
    payload = {
        "owner_write": group_pk,
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
    if response.status_code != 201:
        logger.error("Non 201 return code.")
        return

    json = response.json()
    if 'pk' in json:
        logger.info("Password created!")
        return json['pk']


def main():
    """Populate db according to arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-cu', '--create-user',
        help='Create a user using the provided username + password.',
        action='store_true',
        default=False
    )
    parser.add_argument(
        '-cg', '--create-group',
        help='Create a group using the provided username + password.',
        action='store_true',
        default=False
    )
    parser.add_argument(
        '-l', '--list-passwords',
        help='List all passwords associated to the user.',
        action='store_true',
        default=False
    )
    parser.add_argument(
        '-lg', '--list-groups',
        help='List all groups associated to the user.',
        action='store_true',
        default=False
    )
    parser.add_argument(
        '-pw', '--get-password',
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
        '--url',
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
        '-g', '--group',
        help='The group to store passwords under.',
        action='store',
        default=None
    )
    parser.add_argument(
        '-a', '--associate_user',
        help='The user to associate to a provided group.',
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
        logger.error("Username must be provided!")
        sys.exit(1)

    if args.password is None:
        logger.error("Password must be provided!")
        sys.exit(1)

    if args.verbose > 4:
        logger.warning("Verbosity limited can max be 4")

    logger.debug("Commandline arguments: " + str(args))
    logger.debug("Loading private key from: " + args.private_key)

    # TODO: Gen new key statement here?

    private_key, public_key = load_private_key(
        path=args.private_key,
        password=args.private_key_password
    )

    if args.create_user:
        create_user(args, public_key)

    logger.debug("Private key loading successful")

    if args.create_group:
        create_group(args)

    if args.list_groups:
        list_groups(args)

    if args.list_passwords:
        list_passwords(args)

    if args.associate_user:
        associate_user(args)

    if args.get_password is not None:
        # Parse get_password into python dict
        get_password(args, private_key, public_key, args.get_password)

    if args.store_password is not None:
        store_dict = json.loads(args.store_password)
        store_password(args, private_key, public_key, store_dict)

if __name__ == "__main__":
    main()
