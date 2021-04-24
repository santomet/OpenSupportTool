#DEBUG/TEST MODE: This allows HTTP connection instead of HTTPS
TEST_MODE = True


# to get a string like this run:
# openssl rand -hex 32
# JWT access settings: Secret key is randomly generated on the first instance and saved to the database (see main)
# The algorithm HS256 should not be changed!! Token expiration should be the same on every server
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# How often the server checks for expired ssh authkeys and remove them
CLEANING_LADY_INTERVAL_SECONDS = 60


# SSH For this particular server!
PORT_LIST = list(range(9000, 9101))
SSH_AUTH_KEYS_FILE_PATH = "/opt/INSTALL/sish/deploy/pubkeys/authorized_keys"
SSH_PORT = "2222"
SSH_SERVER = ""  # If kept empty, agents will use the same IP/DOMAIN that they use to connect the API
SSH_SERVER_PUBLIC_FINGERPRINT = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIADBJiJyOZq7Goad/J4IQZaCx70cUjVcMSoIWyzBlKtc"
SSH_SERVER_USERNAME = ""  # A classic SSH server needs this, SISH does not