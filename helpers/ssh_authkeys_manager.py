import os
import tempfile
from sql_orm import schemas
from .settings import AUTH_KEYS_FILE_PATH


def remove_ssh_auth_key(id: int):

    # create the comment for auth_keys identification
    comment = "machine_id:{0}".format(id)

    f = open(AUTH_KEYS_FILE_PATH, mode="r")
    lines = f.readlines()

    id_found_flag = False

    newlines = []

    # Filter out all the appearances of that machine ID we are dealing with
    for l in lines:
        if comment in l:
            id_found_flag = True
        else:
            newlines.append(l)

    if id_found_flag:
        #Ok now just create the file
        f = open(AUTH_KEYS_FILE_PATH, mode="w")
        for l in newlines:
            f.write(l)

        f.close()


def set_ssh_auth_key(id: int, pubkey: str, port: int):

    # remove if there is ID:
    remove_ssh_auth_key(id)

    # create the comment for auth_keys identification
    comment = "machine_id:{0}".format(id)

    # create file if does not exist
    f = open(AUTH_KEYS_FILE_PATH, mode="a")

    auth_key = "permitlisten=\"{0}\",no-pty,command=\"nologin\" {1} {2}".format(port, pubkey, comment)

    f.write("\n")
    f.write(auth_key)
    f.close()
    return True

