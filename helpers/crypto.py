from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from helpers import global_storage
import os
import string

# Number of bytes for the standard random hex
from hashlib import sha1 as hasher
NO_OF_BYTES_HASH = hasher().digest_size
NO_OF_BYTES_RANDOM_STANDARD = 25
NO_OF_BYTES_RANDOM_SHORT = 2
NO_OF_BYTES_HASH_SHORT = 1

async def generate_keypair():
    key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=2048
    )
    private_key = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption())
    public_key = key.public_key().public_bytes(
        crypto_serialization.Encoding.OpenSSH,
        crypto_serialization.PublicFormat.OpenSSH
    )

    return private_key, str(public_key, encoding="utf-8")


def generate_random_short_hex():
    """Generates short random hex"""
    return bytes.hex(os.urandom(NO_OF_BYTES_RANDOM_SHORT))


def generate_random_custom_hex(noofbytes: int):
    return bytes.hex(os.urandom(noofbytes))


def generate_random_standard_hex():
    """Generates standard random value used throughout the application. See no_of_bytes_random, change makes
    the database unusable"""
    return bytes.hex(os.urandom(NO_OF_BYTES_RANDOM_STANDARD))


def generate_provable_token(short: bool = False):
    """Returns a new randomly generated token.
    The token is in form [HASH of PASSWORD + RANDOM][RANDOM]"""
    if global_storage.db_token_check_password:
        rand1 = generate_random_short_hex() if short else generate_random_standard_hex()
        h = hasher(bytes.fromhex(global_storage.db_token_check_password + rand1)).hexdigest()
        return (h[:(NO_OF_BYTES_HASH_SHORT*2)] if short else h) + rand1
    else:
        return None


def prove_token(token: str):
    """If the hash is in a correct form: [HASH of PASSWORD + RANDOM][RANDOM] it checks
    whether the hash corresponds to the hash of [PASSWORD][RANDOM]. The lengths are constants in this file"""
    short = False
    if len(token) is ((NO_OF_BYTES_HASH + NO_OF_BYTES_RANDOM_STANDARD) * 2):
        short = False
    elif len(token) is ((NO_OF_BYTES_HASH_SHORT + NO_OF_BYTES_RANDOM_SHORT) * 2):
        short = True
    else:
        return False

    if short:
        h = token[:(NO_OF_BYTES_HASH_SHORT*2)]
        rand1 = token[(NO_OF_BYTES_HASH_SHORT*2):]
        h2 = hasher(bytes.fromhex(global_storage.db_token_check_password + rand1)).hexdigest()
        return h2[:(NO_OF_BYTES_HASH_SHORT*2)] == h
    else:
        h = token[:(NO_OF_BYTES_HASH*2)]
        rand1 = token[(NO_OF_BYTES_HASH*2):]
        h2 = hasher(bytes.fromhex(global_storage.db_token_check_password + rand1)).hexdigest()
        return h2 == h

