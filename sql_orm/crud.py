from sqlalchemy.orm import Session, relationship, deferred, defer, undefer, load_only
from sqlalchemy.sql.operators import ColumnOperators

from . import models, schemas

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# helpers --------------------------------------------------------


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


# Main password for checking the correctness of tokens

def tokenpass_get(db: Session):
    return db.query(models.TokenCheckPassword).first()


def tokenpass_set(db: Session, password: str):
    tokenpass = models.TokenCheckPassword(password=password)
    db.add(tokenpass)
    db.commit()
    db.refresh(tokenpass)
    return tokenpass


# Users --------------------------------------------------------------


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
    db.refresh(user_group)
    return user_group

def user_group_list(db: Session):
    return db.query(models.UserGroup).all()


def user_group_get(db: Session, group_id: int):
    return db.query(models.UserGroup).filter(models.UserGroup.id == group_id).first()


def user_group_delete(db: Session, group_id: int):
    ret = db.query(models.UserGroup).filter(models.UserGroup.id == group_id).delete()
    db.commit()
    return ret


def user_add_to_group(db: Session, group_id: int, user_id: int):
    user_group_association = models.UserGroupAssociation(user_id=user_id, group_id=group_id)
    db.add(user_group_association)
    db.commit()
    db.refresh(user_group_association)
    return user_group_association


def user_remove_from_group(db: Session, group_id: int, user_id: int):
    ret = db.query(models.UserGroupAssociation).filter(
        models.UserGroupAssociation.user_id == user_id,
        models.UserGroupAssociation.group_id == group_id
    ).delete()
    db.commit()
    return ret

def user_get_group_association(db: Session, group_id: int, user_id: int):
    return db.query(models.UserGroupAssociation).filter(
        models.UserGroupAssociation.user_id == user_id,
        models.UserGroupAssociation.group_id == group_id
    ).first()

# MACHINES--------------------------------------------------------------------------


def machine_create(db: Session, machine: schemas.MachineAfterCreate, token: str):
    db_machine = models.Machine(one_time_installer_token=machine.one_time_installer_token,
                                token=token, title=machine.title, description=machine.description, directory_id=machine.directory_id)
    db.add(db_machine)
    db.commit()
    db.refresh(db_machine)
    machine_full = schemas.Machine.from_orm(db_machine)
    return machine_full


def machine_update(db: Session, machine: models.Machine):
    machine_old: models.Machine = db.query(models.Machine).filter(models.Machine.id == machine.id).first()
    if not machine_old:
        return False
    machine_old = machine
    db.commit()
    return True


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
    return db.query(models.Machine).options(undefer("token")).filter(models.Machine.one_time_installer_token == token).first()


def machine_set_new_installer_token(db: Session, machine_id: int, token: str):
    machine = db.query(models.Machine).options(undefer("one_time_installer_token")) \
        .filter(models.Machine.id == machine_id).first()
    machine.one_time_installer_token = token
    db.commit()
    return machine


def machine_get_by_token(db: Session, token: str):
    return db.query(models.Machine).options(undefer("token")).filter(
            models.Machine.token == token).first()


# MACHINE DIRECTOREIS--------------------------------------------------------------------

def directory_add(db: Session, name: str, parent_id: int = None):
    db_directory = models.MachineDirectory(name=name, parent_id=parent_id)
    db.add(db_directory)
    db.commit()
    db.refresh(db_directory)
    return db_directory


def directory_get(db: Session, directory_id: int):
    return db.query(models.MachineDirectory).filter(models.MachineDirectory.id == directory_id).first()


def directory_get_all(db: Session):
    return db.query(models.MachineDirectory).filter(models.MachineDirectory.parent_id == None).all()


def directory_remove(db: Session, id: int):
    ret = db.query(models.MachineDirectory).filter(models.MachineDirectory.id == id).delete()
    db.commit()
    return ret


# ACCESSES--------------------------------------------------------------------------
# Accessess are only between the groups of users and the directories

def access_add(db: Session, access: schemas.Access):
    db_access = models.Access(**access.dict())
    db.add(db_access)
    db.commit()
    db.refresh(db_access)
    return db_access


def access_get_by_id(db: Session, access_id: int):
    return db.query(models.Access).filter(models.Access.id == access_id).first()


def access_get(db: Session, access_id: int = None, user_group_id: int = None, machine_directory_id: int = None):
    filters = []
    if access_id is not None:
        filters.append(models.Access.id == access_id)
    if user_group_id is not None:
        filters.append(models.Access.user_group_id == user_group_id)
    if machine_directory_id is not None:
        filters.append(models.Access.machine_directory_id == machine_directory_id)

    if len(filters) <= 0:
        return False

    return db.query(models.Access).filter(*filters).first()


def access_delete(db: Session, access_id: int):
    ret = db.query(models.Access).filter(models.Access.id == access_id).delete()
    db.commit()
    return ret


# Tunnels --------------------------------------------------------------------------


def tunnel_get_used_reverse_ports(db: Session):
    filt = models.Tunnel.connection_state != models.ConnectionStateEnum.disconnected
    return db.query(models.Tunnel).filter(filt).options(load_only("reverse_port")).all()


def tunnels_list(db: Session, machine_id: int = None, connection_states: [models.ConnectionStateEnum] = None):
    filts = []
    if machine_id:
        filts.append(models.Tunnel.machine_id == machine_id)
    if connection_states:
        filts.append(models.Tunnel.connection_state.in_(connection_states))

    return db.query(models.Tunnel).filter(*filts).all()


def tunnel_add(db: Session, tunnel: models.Tunnel):
    db.add(tunnel)
    db.commit()
    db.refresh(tunnel)
    return tunnel.id


def tunnel_get_request_by_id(db: Session, connection_id: int):
    return db.query(models.Tunnel).filter(models.Tunnel.id == connection_id).first()


def tunnel_update(db: Session, tunnel: models.Tunnel):
    tunnel_old = db.query(models.Tunnel).filter(models.Tunnel.id == tunnel.id).first()
    if not tunnel_old:
        return False
    tunnel_old = tunnel
    db.commit()
    return True


def tunnel_update_connection_state(db: Session, connection_id: int, connection_state: models.ConnectionStateEnum):
    connection = db.query(models.Tunnel).filter(models.Tunnel.id == connection_id).first()
    connection.connection_state = connection_state
    db.commit()
    return connection


def tunnels_remove_connection(db: Session, connection_id: int):
    ret = db.query(models.Tunnel).filter(models.Tunnel.id == connection_id).delete()
    db.commit()
    return ret
