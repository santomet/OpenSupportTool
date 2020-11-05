import os
import tempfile
from sql_orm import schemas
from .settings import SISH_SSH_PORT


async def remove_file(f: str):
    os.remove(f)


async def generate_installer_file(machine: schemas.Machine, remote_hostname: str, remote_http_port: str, sish_local_port: str):
    # this is going to be scripting hell
    f = tempfile.NamedTemporaryFile(delete=False, mode="w")

    s = '''\
#! /bin/bash
echo "Hey there wisconsin!!!"
REMOTE_PUBLICKEY="{0}"
ONETIME_SISH_KEY_INSTALL_TOKEN="{1}"
STATS_TOKEN="{2}"
REMOTE_HOST="{3}"
REMOTE_PORT="{4}"
SISH_REMOTE_PORT="{5}"
SISH_LOCAL_PORT="{6}"

'''
    s = s.format(machine.public_key_remote, machine.one_time_sish_set_token, machine.stats_identifier,
                 remote_hostname, remote_http_port, SISH_SSH_PORT, sish_local_port)
    s += \
'''
# First install the key for remote access:
echo Installing trusted remote access key to authorized_keys
mkdir -p ~/.ssh
touch ~/.ssh/authorized_keys
echo $REMOTE_PUBLICKEY >> ~/.ssh/authorized_keys

echo Generating key if not present
# Now generate our own! (if we do not have any)
cat /dev/zero | ssh-keygen -q -N ""

# save the key to var
SISH_KEY=$( cat ~/.ssh/id_rsa.pub )

echo Registering our key with remote sish server
# register ourselves with the server: TODO (we need also port for that :( )
curl -X POST "http://$REMOTE_HOST:$REMOTE_PORT/machines/set_sish_pubkey" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{\\\"pubkey\\\":\\\"$SISH_KEY\\\",\\\"token\\\":\\\"$ONETIME_SISH_KEY_INSTALL_TOKEN\\\"}"

# And the big TODO: add autossh to cron :) and we are pretty much done here don't we?
# But for now let's just and only connect to ssh:
ssh -p $SISH_REMOTE_PORT -R $SISH_LOCAL_PORT:localhost:22 $REMOTE_HOST

'''


    f.write(s)

    f.close()
    return f
