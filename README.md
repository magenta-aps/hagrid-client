# hagrid-client - Password Client
hagrid-client is a development client for interacting wiht the hagrid server,
via the exposed REST API. Functionality is very limited.

For more information see: https://github.com/magenta-aps/hagrid

The code is in no way ready for use.

Experimenting
=============
* Clone the repository
* Install packages
* Run `client.py`

```
usage: client.py [-h] [-l] [-g GET_PASSWORD] [-s STORE_PASSWORD] [-a URL]
                 [-u USERNAME] [-p PASSWORD] [-k PRIVATE_KEY]
                 [-i PRIVATE_KEY_PASSWORD] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -l, --list-passwords  List all passwords associated to the user.
  -g GET_PASSWORD, --get-password GET_PASSWORD
                        Get a password by providing its primary key.
  -s STORE_PASSWORD, --store-password STORE_PASSWORD
                        Store a password by providing a json object.
  -a URL, --url URL     The url of the server.
  -u USERNAME, --username USERNAME
                        The username used to log into the server.
  -p PASSWORD, --password PASSWORD
                        The password used to log into the server.
  -k PRIVATE_KEY, --private-key PRIVATE_KEY
                        Path to the private key to use.
  -i PRIVATE_KEY_PASSWORD, --private-key-password PRIVATE_KEY_PASSWORD
                        Password to unlock private key (if required).
  -v, --verbose         Verbosity of the output.
```

Usage scenario, first create a user (assumes a private key is found in `~/.ssh/id_rsa`:
```
$ ./client.py -u emil -p password1 --create-user
```
Then store a password:
```
$ ./client.py -u emil -p password1 --store-password '{"username": "Skeen", "password": "password2", "title": "Github Login", "url": "https://github.com/"}'
```

Then list passwords available to us:
```
$ ./client.py -u emil -p password1 --list-passwords

Passwords:
* 1: Google account
* 2: Github Login
```

Finally request the stored password:
```
$ ./client.py -u emil -p password1 --get-password 2

Found password:
- title: Github Login
- url: https://github.com/
- notes: 
- username: Skeen
- password: password2
```

Getting help
============
Browse the AUTHORS file, and ask around the office.
