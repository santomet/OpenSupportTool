import os
import tempfile
from sql_orm import schemas
from .settings import SSH_AUTH_KEYS_FILE_PATH

import datetime
import re


def remove_expired_ssh_auth_keys():

    f = open(SSH_AUTH_KEYS_FILE_PATH, mode="r")
    lines = f.readlines()

    id_found_flag = False

    newlines = []

    # Filter out all the appearances of that machine ID we are dealing with
    for l in lines:
        matchobj = re.match(r'timeout:(.*)$', l)
        if matchobj:
            to = datetime.datetime.fromisoformat(matchobj.group(1))
            if to < datetime.datetime.utcnow():
                id_found_flag = True
        else:
            newlines.append(l)

    if id_found_flag:
        #Ok now just create the file
        f = open(SSH_AUTH_KEYS_FILE_PATH, mode="w")
        for l in newlines:
            f.write(l)

        f.close()


def remove_particular_ssh_auth_key(pubkey: str):

    f = open(SSH_AUTH_KEYS_FILE_PATH, mode="r")
    lines = f.readlines()

    id_found_flag = False

    newlines = []

    # Filter out all the appearances of that machine ID we are dealing with
    for l in lines:
        if pubkey in l:
            id_found_flag = True
        else:
            newlines.append(l)

    if id_found_flag:
        #Ok now just create the file
        f = open(SSH_AUTH_KEYS_FILE_PATH, mode="w")
        for l in newlines:
            f.write(l)

        f.close()


def set_ssh_auth_key(timeout: datetime.datetime, pubkey: str, port: int):

    # create the comment for auth_keys identification
    comment = "timeout:{0}".format(timeout.isoformat())

    # create file if does not exist
    f = open(SSH_AUTH_KEYS_FILE_PATH, mode="a")

    auth_key = "permitlisten=\"{0}\",no-pty,command=\"nologin\" {1} {2}".format(port, pubkey, comment)

    f.write("\n")
    f.write(auth_key)
    f.close()
    return True

