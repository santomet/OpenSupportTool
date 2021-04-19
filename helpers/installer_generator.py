import os
import tempfile
from sql_orm import schemas
from .settings import TEST_MODE


async def remove_file(f: str):
    os.remove(f)


async def generate_installer_file(machine: schemas.Machine, remote_hostname: str, remote_http_port: str):
    f = tempfile.NamedTemporaryFile(delete=False, mode="w")
    s = '''\
#! /bin/bash
echo "Hey there delilah!!!"
TOKEN="{0}"
REMOTE_HOST="{1}"
REMOTE_PORT="{2}"
SERVER_PROTOCOL="{3}"
    '''
    s = s.format(machine.token, remote_hostname, remote_http_port, "http://" if TEST_MODE else "https://")
    s += \
        '''
# Make the directory and CD in there
mkdir ~/.OSTAgent
cd ~/.OSTAgent

# Download the agent archive
wget https://github.com/santomet/OpenSupportTool-daemon/archive/refs/tags/v0.1.zip
unzip v0.1.zip
mv OpenSupportTool*/* .
rm -rf OpenSupport*
rm *.zip

# recreate the data.json
rm data.json
cat << EOF > data.json
{"token": "$TOKEN", "server_protocol": "$SERVER_PROTOCOL", "server_domain_ip": "$REMOTE_HOST", "server_port": $REMOTE_PORT, "interval_seconds": 5, "is_installed": false, "tunnels": []}
EOF



# Install all the requirements
sudo apt install python3 python3-pip python3-psutil python3-requests

# Create the service
SYSTEMDFILENAME=/etc/systemd/system/ost-agent.service
echo "[Unit]" | sudo tee $SYSTEMDFILENAME
echo "Description=Open Support Tool Agent" | sudo tee -a $SYSTEMDFILENAME
echo "After=network-online.target ssh.service" | sudo tee -a $SYSTEMDFILENAME
echo "" | sudo tee -a $SYSTEMDFILENAME
echo "[Service]" | sudo tee -a $SYSTEMDFILENAME
echo "User=$USER" | sudo tee -a $SYSTEMDFILENAME
# echo "Environment=\\\"AUTOSSH_GATETIME=0\\\"" | sudo tee -a $SYSTEMDFILENAME
echo "ExecStart = /usr/bin/python3 /home/$USER/.OSTAgent/main.py" | sudo tee -a $SYSTEMDFILENAME
echo 'ExecStop=/bin/kill $MAINPID' | sudo tee -a $SYSTEMDFILENAME
echo "" | sudo tee -a $SYSTEMDFILENAME
echo "[Install]" | sudo tee -a $SYSTEMDFILENAME
echo "WantedBy=multi-user.target" | sudo tee -a $SYSTEMDFILENAME

sudo systemctl daemon-reload
sudo systemctl stop ost-agent.service
sudo systemctl start ost-agent.service
        '''

    f.write(s)

    f.close()
    return f


# async def generate_installer_file_old(machine: schemas.Machine, remote_hostname: str, remote_http_port: str):
#         # this is going to be scripting hell
#         f = tempfile.NamedTemporaryFile(delete=False, mode="w")
#
#         s = '''\
# #! /bin/bash
# echo "Hey there wisconsin!!!"
# REMOTE_PUBLICKEY="{0}"
# ONETIME_SISH_KEY_INSTALL_TOKEN="{1}"
# TOKEN="{2}"
# REMOTE_HOST="{3}"
# REMOTE_PORT="{4}"
# SSH_REMOTE_PORT="{5}"
# SSH_LOCAL_PORT="{6}"
# SSH_PUBLIC_FINGERPRINT="{7}"
#
# '''
#
#     s = s.format(machine.public_key_ssh_tunnel, machine.one_time_set_authkey_token, machine.token,
#                  remote_hostname, remote_http_port, SSH_PORT, 666, SSH_SERVER_PUBLIC_FINGERPRINT)
#     s += \
#         '''
# # First install the key for remote access:
# echo Installing trusted remote access key to authorized_keys
# mkdir -p ~/.ssh
# touch ~/.ssh/authorized_keys
# echo $REMOTE_PUBLICKEY >> ~/.ssh/authorized_keys
#
# echo Generating key if not present
# # Now generate our own! (if we do not have any)
# cat /dev/zero | ssh-keygen -q -N "" -f ~/.ssh/id_rsa_ost-autossh
#
# # save the key to var
# SISH_KEY=$( cat ~/.ssh/id_rsa_ost-autossh.pub )
#
# echo Registering our key with remote sish server
# # register ourselves with the server: TODO (we need also port for that :( )
# curl -X POST "http://$REMOTE_HOST:$REMOTE_PORT/machines/set_sish_pubkey" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{\\\"pubkey\\\":\\\"$SISH_KEY\\\",\\\"token\\\":\\\"$ONETIME_SISH_KEY_INSTALL_TOKEN\\\"}"
#
#
# # register ssh server to known hosts
# echo "[$REMOTE_HOST]:$SSH_REMOTE_PORT $SSH_PUBLIC_FINGERPRINT" >> ~/.ssh/known_hosts
#
#
# # Create a service:
# SYSTEMDFILENAME=/etc/systemd/system/ost-autossh.service
# echo "[Unit]" | sudo tee $SYSTEMDFILENAME
# echo "Description=AutoSSH tunnel service from Open Support Tool" | sudo tee -a $SYSTEMDFILENAME
# echo "After=network-online.target ssh.service" | sudo tee -a $SYSTEMDFILENAME
# echo "" | sudo tee -a $SYSTEMDFILENAME
# echo "[Service]" | sudo tee -a $SYSTEMDFILENAME
# echo "User=$USER" | sudo tee -a $SYSTEMDFILENAME
# echo "Environment=\\\"AUTOSSH_GATETIME=0\\\"" | sudo tee -a $SYSTEMDFILENAME
# echo "ExecStart = /usr/bin/autossh -M 0 -o \\\"ServerAliveInterval 30\\\" -o \\\"ServerAliveCountMax 3\\\" -R $SSH_LOCAL_PORT:localhost:22 $REMOTE_HOST -p $SSH_REMOTE_PORT -i /home/$USER/.ssh/id_rsa_ost-autossh" | sudo tee -a $SYSTEMDFILENAME
# #echo "ExecStop=/bin/kill $MAINPID" | sudo tee -a $SYSTEMDFILENAME
# echo "" | sudo tee -a $SYSTEMDFILENAME
# echo "[Install]" | sudo tee -a $SYSTEMDFILENAME
# echo "WantedBy=multi-user.target" | sudo tee -a $SYSTEMDFILENAME
#
# sudo systemctl daemon-reload
# sudo systemctl stop ost-autossh.service
# sudo systemctl start ost-autossh.service
#
# echo Installed! Please try the connection right now
#
# wait
#
# '''
#
#     f.write(s)
#
#     f.close()
#     return f
