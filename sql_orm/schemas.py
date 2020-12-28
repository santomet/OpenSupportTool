from typing import List, Optional

from pydantic import BaseModel

from .models import AccessTypeEnum


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
