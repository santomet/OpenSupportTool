from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Enum, UniqueConstraint, DateTime, Float
from sqlalchemy.orm import relationship, deferred

from .database import Base
import enum


class AccessTypeEnum(enum.IntEnum):
    """
    Types of authorizations:
    None = 0
    Owner = 4
    Maintainer = 3
    Supporter = 2
    Reporter = 1
    """
    none = 0
    owner = 4
    maintainer = 3  # can do everything except delete and adding new accesses
    supporter = 2  # can control machines but cannot remove or edit them
    reporter = 1  # can see only machine state


class ActionTypeEnum(enum.IntEnum):
    """
    Types of actions:
    Connection = 0
    Restart = 1
    Others TBD
    """
    connection = 0  # asking for a connection
    restart = 1  # reserved TODO


class ConnectionTypeEnum(enum.IntEnum):
    """
    Types of connections:
    SSH Tunnel = 0
    WebRTC = 1 (Not implemented yet)
    """
    ssh_tunnel = 0
    webrtc = 1  # Reserved TODO


class ConnectionStateEnum(enum.IntEnum):
    """
    Connection states:
    Disconnected - Finished and archived = 0
    Requested = 1
    Agent responded, Connection in progress = 2
    Disconnect Has been requested = 3
    """
    disconnected = 0
    requested = 1
    connected = 2  # this means that the agent acknowledges connection
    disconnect_requested = 3  # this means that agent is requested to close the connection


#    def __lt__(self, other):
#        if self.__class__ is other.__class__:
#            return self.value < other.value
#        return NotImplemented


class TokenCheckPassword(Base):
    """Password for fast checking the validity of tokens. There can be only one per db"""
    __tablename__ = "tokencheckpassword"

    id = Column(Integer, primary_key=True)
    password = Column(String)


class User(Base):
    """Description of user"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = deferred(Column(String))
    is_admin = Column(Boolean)
    groups = relationship("UserGroupAssociation", back_populates="user")
    accesses = relationship("Access", back_populates="user")


class UserGroup(Base):
    """Description of a group of users"""
    __tablename__ = "user_groups"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    users = relationship("UserGroupAssociation", back_populates="group")
    accesses = relationship("Access", back_populates="user_group")


class UserGroupAssociation(Base):
    """Association of a user to a user group"""
    __tablename__ = "user_group_associations"

    user_id = Column(Integer, ForeignKey("users.id"), index=True, primary_key=True)
    group_id = Column(Integer, ForeignKey("user_groups.id"), index=True, primary_key=True)
    user = relationship("User", back_populates="groups")
    group = relationship("UserGroup", back_populates="users")


class Access(Base):
    """Description of an access"""
    __tablename__ = "access"

    id = Column(Integer, primary_key=True)
    machine_id = Column(Integer, ForeignKey("machines.id"), index=True)
    machine_group_id = Column(Integer, ForeignKey("machine_groups.id"), index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    user_group_id = Column(Integer, ForeignKey("user_groups.id"), index=True)
    type = Column(Enum(AccessTypeEnum))

    UniqueConstraint('user_id', 'machine_id', name='uix_1')
    UniqueConstraint('user_id', 'machine_group_id', name='uix_2')
    UniqueConstraint('user_group_id', 'machine_id', name='uix_3')
    UniqueConstraint('user_group_id', 'machine_group_id', name='uix_4')

    user = relationship("User", back_populates="accesses")
    user_group = relationship("UserGroup", back_populates="accesses")
    machine = relationship("Machine", back_populates="accesses")
    machine_group = relationship("MachineGroup", back_populates="accesses")


class MachineGroup(Base):
    """Group of machines"""
    __tablename__ = "machine_groups"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    machines = relationship("MachineGroupAssociation", back_populates="group")
    accesses = relationship("Access", back_populates="machine_group")


class MachineGroupAssociation(Base):
    """Association of machine to a machine group"""
    __tablename__ = "machine_group_associations"

    machine_id = Column(Integer, ForeignKey("machines.id"), index=True, primary_key=True)
    machine_group_id = Column(Integer, ForeignKey("machine_groups.id"), index=True, primary_key=True)
    group = relationship("MachineGroup", back_populates="machines")
    machine = relationship("Machine", back_populates="groups")


class Machine(Base):
    """Machine description"""
    __tablename__ = "machines"

    id = Column(Integer, primary_key=True, index=True)

    one_time_installer_token = deferred(Column(String, index=True, unique=True))

    token = deferred(Column(String, index=True, unique=True))

    title = Column(String, index=True)
    description = Column(String)

    last_query_datetime = Column(DateTime)
    last_cpu_percent = Column(Float, default=0.0)
    last_memory_percent = Column(Float, default=0.0)

    agent_user_name = (Column(String, default=""))

    groups = relationship("MachineGroupAssociation", back_populates="machine")
    accesses = relationship("Access", back_populates="machine")
    tunnels = relationship("Tunnel", back_populates="machine")


# Tunnels -----------------------------------------------------------------------------------------------

class Tunnel(Base):
    """This is how a connection is described in the database"""
    __tablename__ = "connections"

    id: Column = Column(Integer, primary_key=True, index=True)
    machine_id = Column(Integer, ForeignKey("machines.id"), index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)

    connection_state = Column(Enum(ConnectionStateEnum), index=True, default=ConnectionStateEnum.disconnected)
    connection_type = Column(Enum(ConnectionTypeEnum))

    port_to_tunnel = Column(Integer)

    temporary_pubkey_for_agent_ssh = Column(String, default="")

    creation_time = Column(DateTime)
    timeout_time = Column(DateTime)

    # These only if this is a SSH tunnel connection.
    reverse_port = Column(Integer, default=0)
    temporary_tunnel_privkey = Column(String, default="")
    temporary_tunnel_pubkey = Column(String, default="")
    # Server-specific
    remote_ssh_fingerprint = Column(String, default="")
    remote_ssh_port = Column(Integer, default=0)
    remote_ssh_server = Column(String, default="")
    remote_ssh_username = Column(String, default="")

    # relationships
    machine = relationship("Machine", back_populates="tunnels")
