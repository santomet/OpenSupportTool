from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Enum
from sqlalchemy.orm import relationship, deferred

from .database import Base
import enum


class AccessTypeEnum(enum.Enum):
    owner = 0
    maintainer = 1  # can do everything except delete
    supporter = 2  # can control machines but cannot remove or edit them
    reporter = 3  # can see only machine state


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = deferred(Column(String))
    is_admin = Column(Boolean)
    groups = relationship("UserGroupAssociation", back_populates="user")
    accesses = relationship("Access", back_populates="user")


class UserGroup(Base):
    __tablename__ = "user_groups"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    users = relationship("UserGroupAssociation", back_populates="group")
    accesses = relationship("Access", back_populates="user_group")


class UserGroupAssociation(Base):
    __tablename__ = "user_group_associations"

    user_id = Column(Integer, ForeignKey("users.id"), index=True, primary_key=True)
    group_id = Column(Integer, ForeignKey("user_groups.id"), index=True, primary_key=True)
    user = relationship("User", back_populates="groups")
    group = relationship("UserGroup", back_populates="users")


class Access(Base):
    __tablename__  = "access"

    id = Column(Integer, primary_key=True)
    machine_id = Column(Integer, ForeignKey("machines.id"), index=True)
    machine_group_id = Column(Integer, ForeignKey("machine_groups.id"), index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    user_group_id = Column(Integer, ForeignKey("user_groups.id"), index=True)
    type = Column(Enum(AccessTypeEnum))

    user = relationship("User", back_populates="accesses")
    user_group = relationship("UserGroup", back_populates="accesses")
    machine = relationship("Machine", back_populates="accesses")
    machine_group = relationship("MachineGroup", back_populates="accesses")


class MachineGroup(Base):
    __tablename__ = "machine_groups"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    machines = relationship("MachineGroupAssociation", back_populates="group")
    accesses = relationship("Access", back_populates="machine_group")


class MachineGroupAssociation(Base):
    __tablename__ = "machine_group_associations"

    machine_id = Column(Integer, ForeignKey("machines.id"), index=True, primary_key=True)
    machine_group_id = Column(Integer, ForeignKey("machine_groups.id"), index=True, primary_key=True)
    group = relationship("MachineGroup", back_populates="machines")
    machine = relationship("Machine", back_populates="groups")


class Machine(Base):
    __tablename__ = "machines"

    id = Column(Integer, primary_key=True, index=True)
    port = Column(Integer, unique=True)

    private_key_remote = deferred(Column(String))
    public_key_remote = deferred(Column(String))
    public_key_sish = deferred(Column(String))

    one_time_sish_set_token = deferred(Column(String, index=True, unique=True))
    one_time_installer_token = deferred(Column(String, index=True, unique=True))

    stats_identifier = deferred(Column(String, index=True, unique=True))

    title = Column(String, index=True)
    description = Column(String)

    groups = relationship("MachineGroupAssociation", back_populates="machine")
    accesses = relationship("Access", back_populates="machine")
