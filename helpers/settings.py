#DEBUG/TEST MODE: This allows HTTP connection instead of HTTPS
TEST_MODE = True

# Auth
# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30



# SSH
PORT_LIST = list(range(9000, 9101))
SSH_AUTH_KEYS_FILE_PATH = "/opt/INSTALL/sish/deploy/pubkeys/authorized_keys"
SSH_PORT = "2222"
SSH_SERVER = ""  # If kept empty, agents will use the same IP/DOMAIN that they use to connect the API
SSH_SERVER_PUBLIC_FINGERPRINT = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIADBJiJyOZq7Goad/J4IQZaCx70cUjVcMSoIWyzBlKtc"
SSH_SERVER_USERNAME = ""  # A classic SSH server needs this, SISH does not