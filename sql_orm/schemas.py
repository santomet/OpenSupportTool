from typing import List, Optional

from pydantic import BaseModel, ValidationError, validator, Field, Json

from .models import AccessTypeEnum, ActionTypeEnum, ConnectionTypeEnum, ConnectionStateEnum
from datetime import datetime

import helpers.settings

# Base: class has common data when creating or reading
# Create: has only when creating
# -: has only when reading


# MACHINES----------------------------------------------


class MachineBase(BaseModel):
    title: str = Field(..., description="Name of a machine")
    description: Optional[str] = Field(None, description="Additional info")
    directory_id: int = Field(1, description="A machine directory where this can be")


    class Config:
        orm_mode = True

class MachineDetails(MachineBase):
    id: int
    last_query_datetime: datetime = Field(None,
                                          description="The UTC datetime of when the computer sent it's query the last time")
    last_cpu_percent: float = Field(0.0, description="The load of CPU at last_query_datetime")
    last_memory_percent: float = Field(0.0, description="The load of memory at last_query_datetime")
    agent_user_name: str = Field(None, description="The username of agent's account (simple SSH login)")

class MachineAfterCreate(MachineBase):
    one_time_installer_token: str = Field(None, description="The Token for downloading the Installer")
    one_time_installer_url: str = Field(None, description="Full URL for downloading the Installer")


class Machine(MachineAfterCreate):
    id: int
    token: str = None


# USERS---------------------------------------------------------------


class UserBase(BaseModel):
    email: str
    username: str
    is_admin: bool


class UserCreate(UserBase):
    password: str


class User(UserBase):
    # def __init__(self, *args, **kwargs):
    #     super().__init__(args, kwargs)
    #     self.groups = None

    id: int
    groups: List

    class Config:
        orm_mode = True


class UserGroup(BaseModel):
    id: int
    name: str

    class Config:
        orm_mode = True

# Directory
class MachineDirectoryCreate(BaseModel):
    name: str = Field("DIR_DEFAULT", description="Name of a machine directory")
    parent_id: int = Field(None, description="Parent Directory ID")


class MachineDirectory(MachineDirectoryCreate):
    id: int = Field(0, description="Machine Directory ID")
    machines: List[MachineDetails] = Field([], description="A list of child machines")
    children: List["MachineDirectory"] = Field([], description="A list of child directories")

    class Config:
        orm_mode = True


class MachineDirectoryForJson(MachineDirectory):
    access_level: AccessTypeEnum = Field(AccessTypeEnum.none, description="The user that got this directory has this access level for it")

MachineDirectory.update_forward_refs()
MachineDirectoryForJson.update_forward_refs()

# ACCESSES-----------------------------------------------------------


class Access(BaseModel):
    machine_directory_id: int = None
    user_group_id: int = None
    type: AccessTypeEnum


# TUNNELS -------------------------------------------------------------------------------------------------------------
# TUNNELS REQUEST MODELS
class TunnelRequest(BaseModel):
    """Model for requesting the tunnel"""
    machine_id: int = Field(..., description="Id of a machine in the DB")
    port_to_tunnel: int = Field(..., description="an auth key that is to be used temporarily. It will be removed "
                                                 "after the tunnel is terminated. Note that this should only be used "
                                                 "if we want to establish an SSH connection to the machine")
    connection_type: ConnectionTypeEnum
    temporary_ssh_pubkey: str = Field("", description="a public key key that is to be used temporarily. It will be removed "
                                                 "after the tunnel is terminated Note that this should only be used "
                                                 "if we want to establish an SSH connection to the machine")
    timeout_seconds: int = Field(3600, description= "Timeout for the tunnel - the tunnel will terminate automatically "
                                                    "after this time. Default is one hour, has to be set between 2 "
                                                    "minutes and 24hours for security purposes")

    # ice_candidates: TBD

    @validator('port_to_tunnel')
    def port_range_check(cls, v: int):
        if v < 1 or v > 65535:
            raise ValueError('Port number is not in range')
        return v

    @validator('timeout_seconds')
    def timeout_validator(cls, v: int):
        if v < 120 or v > 86400:
            raise ValueError('The timeout has to be set between two minutes and 24 hours')
        return v


class TunnelsListRequest(BaseModel):
    """Model by which you can request filtered Tunnel list"""
    machine_id: int = Field(None, description="ID of a machine. Set null if you want to see all")
    connection_states: List[ConnectionStateEnum] = Field(None, description="Connection states you want to see, keep EMPTY! if you want to see all")


# ACTIONS RESPONSE MODELS
class TunnelRequestResponse(BaseModel):
    """
    Model by which the API responds to the request of opening an tunnel if it is successful
    """
    id: int = Field(..., description="db ID for the tunnel. You can terminate the tunnel or prolong it's life "
                                            "with it")
    port_to_tunnel: int = Field(..., description="The port which is tunnelled, just check if it is what you wanted")
    reverse_port: int = Field(..., description="The port on which remote_port is going to be accessible")


class TunnelInfo(BaseModel):
    id: int = Field(..., description="ID of the tunnel")
    machine_id: int = Field(..., description="ID of a machine")
    user_id: int = Field(..., description="ID of user that created the tunnel")
    connection_type: ConnectionTypeEnum
    connection_state: ConnectionStateEnum
    port_to_tunnel: int = Field(..., description="Port which is going to be tunneled")
    creation_time: datetime = Field(None, description="Datetime when the request for tunnel was created")
    timeout_time: datetime = Field(None, description="Datetime when the tunnel should be terminated")
    reverse_port: int = Field(..., description="The port through port_to_tunnel should be accessed")
    remote_ssh_server: str = Field("", description="The host through which the tunnel is accessible")

    class Config:
        orm_mode = True


# AGENT ----------------------------------------------------------------------------------------------------------------
# AGENT QUERY

class AgentInstall(BaseModel):
    token: str = Field("", description="The long term token of Agent")
    agent_user_name: str = Field("", description="The user name which hosts on the agent (may be a subject of change)")


class AgentQuery(BaseModel):
    token: str = Field("", description="The long term token of Agent")
    last_cpu_percent: float = Field(0.0, description="The load of CPU")
    last_memory_percent: float = Field(0.0, description="The actual load of memory")


class AgentTunnelChange(BaseModel):
    token: str = Field("", description="The long term token of Agent")
    tunnel_id: int = Field(0, description="ID of tunnel")
    new_state: ConnectionStateEnum = Field(ConnectionStateEnum.disconnected, description="New state of a tunnel according to the agent")
    remote_ssh_server: str = Field("", description="The remote SSH host that apparently works if the connection has been established")


# RESPONSES TO AGENT

class AgentResponse(BaseModel):
    class Tunnel(BaseModel):
        id: int = Field(0, description="ID of the connection so the agent always knows what is this about")
        connection_type: ConnectionTypeEnum = ConnectionTypeEnum.ssh_tunnel
        connection_state: ConnectionStateEnum = ConnectionStateEnum.requested
        port_to_tunnel: int = Field(0, description="The port to be tunnelled")
        timeout_time: datetime = Field(..., description="The GMT time when the connection has to be terminated")
        temporary_pubkey_for_agent_ssh: str = Field("", description="Optional SSH public key which has to be accepted for incoming SSH connections only during the existence of tunnel")

        # Only for SSH
        temporary_tunnel_privkey: str = Field("", description="Private key that has to be used as authentication to SSH server when creating reverse tunnel, the generation will probably be moved to the agent")
        reverse_port: int = Field(0, description="Port on which local_port will be accessible")
        # Server-specific
        remote_ssh_fingerprint: str = Field("", description="A fingerprint of public SSH server for the known_hosts")
        remote_ssh_port: int = Field(0, description="Port of SSH server which is going to serve the tunnel")
        remote_ssh_server: str = Field("", description="The IP or DOMAIN for the SSH, if empty, use the IP/Domain for the API communication")
        remote_ssh_username: str = Field("", description="The username that is to be used for the login while creating a SSH Tunnel. If empty, agent will not specify anything")

        class Config:
            orm_mode = True

    tunnels_requesting_action: List[Tunnel] = []
    message: str = Field("", description="Optional message sent by the server. If not empty, this should be logged by the agent")
