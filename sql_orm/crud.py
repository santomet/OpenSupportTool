from sqlalchemy.orm import Session,relationship, deferred, defer, undefer, load_only

from . import models, schemas

from passlib.context import CryptContext


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# helpers --------------------------------------------------------


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


# --------------------------------------------------------------


def users_is_empty(db: Session):
    return not db.query(models.User).first()


def user_get(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()


def user_get_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()


def user_get_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def users_get(db: Session, skip: int = 0):
    return db.query(models.User).offset(skip).all()


def user_create(db: Session, user: schemas.UserCreate):
    hashed_password = get_password_hash(user.password)
    db_user = models.User(email=user.email, hashed_password=hashed_password, username=user.username,
                          is_admin=user.is_admin)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def user_change_password(db: Session, username: str, new_password: str):
    hashed_password = get_password_hash(new_password)
    user = db.query(models.User).options(undefer("hashed_password")).filter(models.User.username == username).first()
    user.hashed_password = hashed_password
    db.commit()
    return user


def user_delete(db: Session, username: str):
    ret = db.query(models.User).filter(models.User.username == username).delete()
    db.commit()
    return ret


# USER GROUPS-----------------------------------------------------------------------


def user_group_create(db: Session, group_name: str):
    user_group = models.UserGroup(name=group_name)
    db.add(user_group)
    db.commit()
    db.refresh()
    return user_group


def user_group_delete(db: Session, group_id: int):
    ret = db.query(models.UserGroup).filter(models.UserGroup.id == group_id).delete()
    db.commit()
    return ret


def user_add_to_group(db: Session, group_id: int, user_id: int):
    user_group_association = models.UserGroupAssociation(user_id=user_id, group_id=group_id)
    db.add(user_group_association)
    db.commit()
    db.refresh()
    return user_group_association


def user_remove_from_group(db: Session, group_id: int, user_id: int):
    ret = db.query(models.UserGroupAssociation).filter(
        models.UserGroupAssociation.user_id == user_id,
        models.UserGroupAssociation.group_id == group_id
    ).delete()
    db.commit()
    return ret


# MACHINES--------------------------------------------------------------------------


def machine_create(db: Session, machine: schemas.MachineCreate):
    db_machine = models.Machine(**machine.dict())
    db.add(db_machine)
    db.commit()
    db.refresh(db_machine)
    return db_machine


def machine_delete(db: Session, id: int):
    ret = db.query(models.Machine).filter(models.Machine.id == id).delete()
    db.commit()
    return ret


def machines_get(db: Session, skip: int = 0):
    return db.query(models.Machine).offset(skip).all()


def machines_get_full(db: Session):
    return db.query(models.Machine).options(undefer("*")).all()


def machine_get(db: Session, machine_id: int):
    return db.query(models.Machine).filter(models.Machine.id == machine_id).first()


def machine_get_by_installer_token(db: Session, token: str):
    return db.query(models.Machine).options(undefer("public_key_ssh_tunnel"),
                                            undefer("one_time_set_authkey_token"),
                                            undefer("token"))\
        .filter(models.Machine.one_time_installer_token == token).first()


def machine_get_by_sish_set_token(db: Session, token: str):
    return db.query(models.Machine) \
        .filter(models.Machine.one_time_set_authkey_token == token).first()


def machine_set_new_installer_token(db: Session, machine_id: int, token: str):
    machine = db.query(models.Machine).options(undefer("one_time_installer_token"))\
        .filter(models.Machine.id == machine_id).first()
    machine.one_time_installer_token = token
    db.commit()
    return machine


def machine_set_new_sish_set_token(db: Session, machine_id: int, token: str):
    machine = db.query(models.Machine).options(undefer("one_time_set_authkey_token"))\
        .filter(models.Machine.id == machine_id) \
        .first()
    machine.one_time_set_authkey_token = token
    db.commit()
    return machine


def machine_set_new_sish_public_key(db: Session, machine_id: int, public_key: str):
    machine = db.query(models.Machine).options(undefer("public_key_sish"))\
        .filter(models.Machine.id == machine_id).first()
    machine.public_key_ssh_tunnel = public_key
    db.commit()
    return machine


# MACHINE GROUPS--------------------------------------------------------------------


def machine_group_create(db: Session, machine_group_name: str):
    machine_group = models.MachineGroup(name=machine_group_name)
    db.add(machine_group)
    db.commit()
    db.refresh(machine_group)
    return machine_group


def machine_groups_list(db: Session):
    return db.query(models.MachineGroup).all()


def machine_group_delete(db: Session, machine_group_id: int):
    ret = db.query(models.MachineGroup).filter(models.MachineGroup.id == machine_group_id).delete()
    db.commit()
    return ret


def machine_add_to_group(db: Session, machine_id: int, machine_group_id: int):
    machine_group_association = models.MachineGroupAssociation(machine_id=machine_id, machine_group_id=machine_group_id)
    db.add(machine_group_association)
    db.commit()
    db.refresh(machine_group_association)
    return machine_group_association


def machine_remove_from_group(db: Session, machine_id: int, machine_group_id: int):
    ret = db.query(models.MachineGroupAssociation).filter(models.MachineGroupAssociation.machine_group_id ==
                                                          machine_group_id, models.MachineGroupAssociation.machine_id ==
                                                          machine_id).delete()
    db.commit()
    return ret


# ACCESSES--------------------------------------------------------------------------


def access_add(db: Session, access: schemas.AccessCreate):
    db_access = models.Access(**access.dict())
    db.add(db_access)
    db.commit()
    db.refresh(db_access)
    return db_access


def access_get_by_id(db: Session, access_id: int):
    return db.query(models.Access).filter(models.Access.id == access_id).first()


def access_get(db: Session, access_id: int = None, user_id: int = None, user_group_id: int = None,
               machine_id: int = None, machine_group_id: int = None):

    filters = []
    if access_id is not None:
        filters.append(models.Access.id == access_id)
    if user_id is not None:
        filters.append(models.Access.user_id == user_id)
    if user_group_id is not None:
        filters.append(models.Access.user_group_id == user_group_id)
    if machine_id is not None:
        filters.append(models.Access.machine_id == machine_id)
    if machine_group_id is not None:
        filters.append(models.Access.machine_group_id == machine_group_id)

    if len(filters) <= 0:
        return False

    return db.query(models.Access).filter(*filters).first()


def access_delete(db: Session, access_id: int):
    ret = db.query(models.Access).filter(models.Access.id == access_id).delete()
    db.commit()
    return ret

# Connections --------------------------------------------------------------------------


def connections_get_used_ports(db: Session):
    return db.query(models.Connection).options(load_only("port")).all()


def connections_add_request(machine_id: int, user_id: int, connection_type: models.ConnectionTypeEnum,
                            remote_port: int, ssh_tunnel_port: int, db: Session):
    connection = models.Connection(machine_id=machine_id, user_id=user_id,
                                   connection_state=models.ConnectionStateEnum.requested,
                                   connection_type=connection_type, remote_port=remote_port,
                                   ssh_tunnel_port=ssh_tunnel_port)

    db.add(connection)
    db.commit()
    db.refresh(connection)
    return connection


def connections_get_request_by_id(connection_id: int, db: Session):
    return db.query(models.Connection).filter(models.Connection.id == connection_id).first()


def connections_update_connection_state(connection_id: int, connection_state: models.ConnectionStateEnum, db: Session):
    connection = db.query(models.Connection).filter(models.Connection.id == connection_id).first()
    connection.connection_state = connection_state
    db.commit()
    return connection


def connection_remove_connection(connection_id: int, db: Session):
    ret = db.query(models.Connection).filter(models.Connection.id == connection_id).delete()
    db.commit()
    return ret

