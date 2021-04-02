from typing import List, Optional

from pydantic import BaseModel

from .models import AccessTypeEnum, ActionTypeEnum, ConnectionTypeEnum


# Base: class has common data when creating or reading
# Create: has only when creating
# -: has only when reading


# MACHINES----------------------------------------------


class MachineBase(BaseModel):
    title: str
    description: Optional[str] = None

    public_key_ssh_tunnel: str = None

    one_time_set_authkey_token: str = None  # used only once
    one_time_installer_token: str = None

    token: str


class MachineCreate(MachineBase):
    pass


class Machine(MachineBase):
    id: int

    class Config:
        orm_mode = True


# USERS---------------------------------------------------------------


class UserBase(BaseModel):
    email: str
    username: str
    is_admin: bool


class UserCreate(UserBase):
    password: str


class User(UserBase):
    id: int

    class Config:
        orm_mode = True


# ACCESSES-----------------------------------------------------------


class AccessBase(BaseModel):
    machine_id: int = None
    machine_group_id: int = None
    user_id: int = None
    user_group_id: int = None
    type: AccessTypeEnum


class AccessCreate(AccessBase):
    pass


class Access(AccessBase):
    pass


# RESPONSES TO AGENT

class AgentResponse(BaseModel):
    class Action(BaseModel):
        class ConnectionDetails(BaseModel):
            connection_type: ConnectionTypeEnum = ConnectionTypeEnum.ssh_tunnel
            domain_ip: str = "0.0.0.0"
            local_port: int = 0
            timeout: int = 0

            remote_ssh_port: int = 0  # these two only for SSH
            remote_reverse_port: int = 0

            ice_candidates: List[str] = []  # TBD for ICE protocol

        action_type: ActionTypeEnum = ActionTypeEnum.connection
        connection: ConnectionDetails = None

    agent_found: bool = False
    has_actions: bool = False
    message: str = ""
    actions: List[Action] = []
