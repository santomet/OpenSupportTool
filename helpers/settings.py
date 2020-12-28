# Auth
# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Machines
PORT_LIST = list(range(9000, 9101))

# SSH
AUTH_KEYS_FILE_PATH = "/opt/INSTALL/sish/deploy/pubkeys/authorized_keys"
SSH_PORT = "2222"
SSH_SERVER_PUBLIC_FINGERPRINT = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIADBJiJyOZq7Goad/J4IQZaCx70cUjVcMSoIWyzBlKtc"