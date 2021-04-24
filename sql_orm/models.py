from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Enum, UniqueConstraint, DateTime, Float, Table
from sqlalchemy.orm import relationship, deferred, backref

from .database import Base
import enum


class AccessTypeEnum(enum.IntEnum):
    """
    Types of authorizations:
    Maintainer = 3
    Supporter = 2
    Reporter = 1
    """
    admin = 10  # Internal purposes
    maintainer = 3  # can do everything except deleting machines and modifying accesses. Can create new machine in a directory
    supporter = 2  # can control machines but cannot edit them
    reporter = 1  # can see only machine state
    none = 0


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

# Auth secrets:

class TokenCheckPassword(Base):
    """Password for fast checking the validity of tokens. There can be only one per db"""
    __tablename__ = "tokencheckpassword"

    id = Column(Integer, primary_key=True)
    password = Column(String)

class JWTSecretPassword(Base):
    """The secret used for JWT auth"""
    __tablename__ = "jwtcheckpassword"

    id = Column(Integer, primary_key=True)
    password = Column(String)



# USER
class User(Base):
    """Description of user"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = deferred(Column(String))
    is_admin = Column(Boolean)
    groups = relationship("UserGroup", backref="users", secondary="user_group_associations")


class UserGroup(Base):
    """Description of a group of users"""
    __tablename__ = "user_groups"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    accesses = relationship("Access", back_populates="group")
    # users = relationship("UserGroupAssociation", back_populates="group")


class UserGroupAssociation(Base):
    """Association of a user to a user group"""
    __tablename__ = "user_group_associations"

    user_id = Column(Integer, ForeignKey("users.id"), index=True, primary_key=True)
    group_id = Column(Integer, ForeignKey("user_groups.id"), index=True, primary_key=True)
    # user = relationship("User", back_populates="groups")
    # group = relationship("UserGroup", back_populates="users")


class Access(Base):
    """Description of an access"""
    __tablename__ = "access"

    id = Column(Integer, primary_key=True)
    machine_directory_id = Column(Integer, ForeignKey("machine_directory.id"), index=True)
    user_group_id = Column(Integer, ForeignKey("user_groups.id"), index=True)
    type = Column(Enum(AccessTypeEnum))

    UniqueConstraint('user_group_id', 'machine_id', name='uix_1')
    UniqueConstraint('user_group_id', 'machine_directory_id', name='uix_2')

    group = relationship("UserGroup", back_populates="accesses")
    directory = relationship("MachineDirectory", back_populates="accesses")

# Machines

class MachineDirectory(Base):
    """The tree-able directory for machines"""
    __tablename__ = "machine_directory"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, default="Default")

    parent_id = Column(Integer, ForeignKey("machine_directory.id"), default=None)

    children = relationship("MachineDirectory", backref=backref("parent", remote_side=[id]))
    machines = relationship("Machine", back_populates="directory")
    accesses = relationship("Access", back_populates="directory")


class Machine(Base):
    """Machine description"""
    __tablename__ = "machines"

    id = Column(Integer, primary_key=True, index=True)
    directory_id = Column(Integer, ForeignKey("machine_directory.id"), nullable=False)

    one_time_installer_token = deferred(Column(String, index=True, unique=True))

    token = deferred(Column(String, index=True, unique=True))

    title = Column(String, index=True)
    description = Column(String)

    last_query_datetime = Column(DateTime)
    last_cpu_percent = Column(Float, default=0.0)
    last_memory_percent = Column(Float, default=0.0)

    agent_user_name = (Column(String, default=""))

#    groups = relationship("MachineGroupAssociation", back_populates="machine")
    directory = relationship("MachineDirectory", back_populates="machines")
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
