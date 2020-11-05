import os
import tempfile
from sql_orm import schemas
from .settings import PATH_TO_SISH_PUBKEYS_DIRECTORY


def set_sish_pubkey(id: int, pubkey: str):
    path = os.path.join(PATH_TO_SISH_PUBKEYS_DIRECTORY, str(id))
    f = open(path, mode="w")
    f.write(pubkey)
    f.close()
    return True

