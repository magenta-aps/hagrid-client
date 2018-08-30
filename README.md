hagrid-client - Password Client
===============================
hagrid-client is a development client for interacting wiht the hagrid server,
via the exposed REST API. Functionality is very limited.

For more information see: https://github.com/magenta-aps/hagrid

The code is in no way ready for use.

# Experimenting
* Clone the repository
* Install packages
* Run `client.py`

```
usage: client.py [-h] [-cu] [-cg] [-l] [-lg] [-pw GET_PASSWORD]
                 [-s STORE_PASSWORD] [--url URL] [-u USERNAME] [-p PASSWORD]
                 [-g GROUP] [-a ASSOCIATE_USER] [-k PRIVATE_KEY]
                 [-i PRIVATE_KEY_PASSWORD] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -cu, --create-user    Create a user using the provided username + password.
  -cg, --create-group   Create a group using the provided username + password.
  -l, --list-passwords  List all passwords associated to the user.
  -lg, --list-groups    List all groups associated to the user.
  -pw GET_PASSWORD, --get-password GET_PASSWORD
                        Get a password by providing its primary key.
  -s STORE_PASSWORD, --store-password STORE_PASSWORD
                        Store a password by providing a json object.
  --url URL             The url of the server.
  -u USERNAME, --username USERNAME
                        The username used to log into the server.
  -p PASSWORD, --password PASSWORD
                        The password used to log into the server.
  -g GROUP, --group GROUP
                        The group to store passwords under.
  -a ASSOCIATE_USER, --associate_user ASSOCIATE_USER
                        The user to associate to a provided group.
  -k PRIVATE_KEY, --private-key PRIVATE_KEY
                        Path to the private key to use.
  -i PRIVATE_KEY_PASSWORD, --private-key-password PRIVATE_KEY_PASSWORD
                        Password to unlock private key (if required).
  -v, --verbose         Verbosity of the output.
```

## Create a user
To create a user:
```
$ ./client.py -u emil -p password1 --create-user
```
This assumes a passwordless key can be found in `~/.ssh/id_rsa`.
If this is not the case, the key can be provided via the `-k` argument.
If the key is password protected, the password can be provided via the `-i` argument.

This will create a new user called: `emil`.

## Creating groups and associating users
To create a new group:
```
$ ./client.py -u emil -p password1 --group groupname --create-group
```
This will create a new group called `groupname` with `emil` as the sole member.

### Associate users with groups
To utilize the potential of groups, we need to add more members:
To add a member to an existing group:
```
$ ./client.py -u emil -p password1 --group groupname --associate_user username
```
This is currently only available for groups with no passwords stored.

This will associate the user `username` with the group `groupname`, and thus
all passwords created in this group will be shared between `emil` and `username`.


## Storing a password
To store a password in an existing group:
```
$ ./client.py -u emil -p password1 --store-password '{"username": "Skeen", "password": "password2", "title": "Github Login", "url": "https://github.com/"}'
```
Optionally the argument `--group groupname` can be provided to store the password
in the specified group, rather than in the users personal group.

## Listing passwords
To list passwords available to us:
```
$ ./client.py -u emil -p password1 --list-passwords

Passwords:
|
| emil:
|--- 1: Google account
|--- 2: Github Login
|
| project_name:
|--- 3: Server login
```
The output is grouped by groups, with all passwords listed under each group.

## Retriving passwords
To retrieve a stored password:
```
$ ./client.py -u emil -p password1 --get-password 2

Found password: password2
```
Where `2` is the ID of the password as returned by the `--list-passwords` command.


Getting help
============
Browse the AUTHORS file, and ask around the office.
