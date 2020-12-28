from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Enum, UniqueConstraint
from sqlalchemy.orm import relationship, deferred

from .database import Base
import enum


class AccessTypeEnum(enum.IntEnum):
    """Types of authorizations"""
    none = 0
    owner = 4
    maintainer = 3  # can do everything except delete and adding new accesses
    supporter = 2  # can control machines but cannot remove or edit them
    reporter = 1  # can see only machine state


class ConnectionTypeEnum(enum.IntEnum):
    """Types of connections"""
    ssh_tunnel = 0
    webrtc = 1  # Reserved TODO


class ConnectionStateEnum(enum.IntEnum):
    """Connection states"""
    disconnected = 0
    requested = 1
    connected = 2  # this means that the agent acknowledges connection
    disconnect_requested = 3  # this means that agent is requested to close the connection


#    def __lt__(self, other):
#        if self.__class__ is other.__class__:
#            return self.value < other.value
#        return NotImplemented


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

    public_key_ssh_tunnel = deferred(Column(String))

    one_time_set_authkey_token = deferred(Column(String, index=True, unique=True))
    one_time_installer_token = deferred(Column(String, index=True, unique=True))

    token = deferred(Column(String, index=True, unique=True))

    title = Column(String, index=True)
    description = Column(String)

    groups = relationship("MachineGroupAssociation", back_populates="machine")
    accesses = relationship("Access", back_populates="machine")


# Connections -----------------------------------------------------------------------------------------------

class Connection(Base):
    """This is how a connection is described in the database"""
    __tablename__ = "connections"

    id = Column(Integer, primary_key=True, index=True)
    machine_id = Column(Integer, ForeignKey("machines.id"), index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)

    connection_state = Column(Enum(ConnectionStateEnum), index=True, default=ConnectionStateEnum.disconnected)
    connection_type = Column(Enum(ConnectionTypeEnum))
    remote_port = Column(Integer)

    # If this is a SSH tunnel connection. Otherwise zero
    ssh_tunnel_port = Column(Integer, default=0)



