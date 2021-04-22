import random
import string

from fastapi import APIRouter, Depends, Request, BackgroundTasks, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel

from helpers import installer_generator, ssh_authkeys_manager, crypto
from sql_orm import crud, schemas, models
from sql_orm.database import get_db
from .users import get_current_user
from typing import List

router = APIRouter()


# HELPERS ---------------------------------------------------------------------------


def get_access_level(db: crud.Session, user_id: int, machine_id: int = None, directory_id: int = None):
    user: models.User = crud.user_get(db, user_id)
    if user.is_admin:
        return models.AccessTypeEnum.admin

    if bool(machine_id) == bool(directory_id):  # XOR - only one of them might be specified
        return models.AccessTypeEnum.none

    highest_access = models.AccessTypeEnum.none

    machine: models.Machine = crud.machine_get(db, machine_id)
    directory_db: models.MachineDirectory = crud.directory_get(db, directory_id)
    if (bool(machine_id) and not machine) or (bool(directory_id) and not directory_db):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The machine or directory nas not been found",
        )

    # First get all the accesses from the groups in which the user is
    user_accesses: [models.Access] = []

    g: models.UserGroup
    if user.groups:
        for g in user.groups:
            user_accesses.extend(g.accesses)

    # Now crawl from the machine up and find the highest access
    pdir: models.MachineDirectory = machine.directory if machine_id else directory_db
    a: models.Access
    while pdir:
        for a in pdir.accesses:
            if a in user_accesses and a.type > highest_access:
                highest_access = a.type
        pdir = pdir.parent

    return highest_access


# -----------------------------------------------------------------------------------


@router.get("/list", response_model=List[schemas.MachineDetails])
async def get_machines_list(current_user: schemas.User = Depends(get_current_user), db: crud.Session = Depends(get_db)):
    """Lists all the machines out of their directories: only Administrators can do this, mainly for debug purposes, should not be used in the client"""
    if current_user.is_admin:
        return crud.machines_get(db)
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to do this operation",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.get("/structured", response_model=List[schemas.MachineDirectoryForJson])
async def get_structured_machine_list(user_group_id: int = None, current_user: schemas.User = Depends(get_current_user),
                                      db: crud.Session = Depends(get_db)):
    if not current_user.is_admin and not user_group_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to list all directories",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user_group_id:
        return crud.directory_get_all(db)

    group_db: models.UserGroup = crud.user_group_get(db, user_group_id)

    if not group_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The user group has not been found",
        )

    if group_db not in current_user.groups and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have any authorization for this particular group",
            headers={"WWW-Authenticate": "Bearer"},
        )

    ret: List[schemas.MachineDirectoryForJson] = []
    a: models.Access
    for a in group_db.accesses:
        ret.append(a.directory)
        ret[-1].access_level = a.type

    return ret


@router.put("/add_machine/", response_model=schemas.Machine)
async def add_machine(machine: schemas.MachineBase, request: Request,
                      current_user: schemas.User = Depends(get_current_user),
                      db: crud.Session = Depends(get_db)):
    """
    Adds a machine with certain name, description and then returns a whole machine object with generated values.
    Only an administrator or an maintainer of certain directory can do that. A machine has to be in some directory
    """

    required_level = models.AccessTypeEnum.admin if not machine.directory_id else models.AccessTypeEnum.maintainer
    if get_access_level(db, user_id=current_user.id, directory_id=machine.directory_id) < required_level:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have any authorization for creating a machine here",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not machine.directory_id or not crud.directory_get(db, machine.directory_id):
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail="The specified directory does not exist: A machine must be in a directory",
        )

    machine_create = schemas.MachineAfterCreate(**dict(machine))
    # generate random token for downloading the install script
    one_time_installer_token = crypto.generate_provable_token(True)
    machine_create.one_time_installer_token = one_time_installer_token
    # now generate random token for sending stats
    token: str = crypto.generate_provable_token(False)

    machine_full: schemas.Machine = crud.machine_create(db, machine_create, token)

    # lastly add the url for convenience
    machine_full.one_time_installer_url = ("https://" + str(request.url.hostname) + ":" + str(request.url.port) +
                                           "/machines/installer/" + one_time_installer_token)

    return machine_full


@router.delete("/remove_machine")
async def remove_machine(machine_id: int, current_user: schemas.User = Depends(get_current_user),
                         db: crud.Session = Depends(get_db)):
    # only an admin can do this
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to remove machines. Contact the administrator",
            headers={"WWW-Authenticate": "Bearer"},
        )

    ret = crud.machine_delete(db, machine_id)
    if not ret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Machine not found"
        )


@router.get("/installer/{one_time_installer_token}")  # NO AUTH!!!!
async def download_installer(one_time_installer_token: str, request: Request, background_tasks: BackgroundTasks,
                             db: crud.Session = Depends(get_db)):
    """
    Downloads an installer file
    """
    if not crypto.prove_token(one_time_installer_token):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found"
        )

    machine: schemas.Machine = crud.machine_get_by_installer_token(db, one_time_installer_token)
    if not machine:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found"
        )

    file = installer_generator.generate_installer_file(machine, request.url.hostname, request.url.port)
    crud.machine_set_new_installer_token(db, machine.id, None)
    background_tasks.add_task(installer_generator.remove_file, file.name)  # this closes file after returning a response
    return FileResponse(path=file.name, filename="installer.sh")



@router.get("/generate_installer_link/")
async def generate_installer_link(machine_id: int, current_user: schemas.User = Depends(get_current_user),
                                  db: crud.Session = Depends(get_db)):
    access_type = get_access_level(db, user_id=current_user.id, machine_id=machine_id)

    if access_type < models.AccessTypeEnum.maintainer:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to do this operation",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # now generate random token for downloading the install script
    one_time_installer_token = crypto.generate_provable_token(True)

    crud.machine_set_new_installer_token(db, machine_id, one_time_installer_token)

    return {"machine_id": machine_id, "one_time_installer_token": one_time_installer_token}


@router.put("/add_directory", response_model=schemas.MachineDirectory)
async def add_directory(name: str, parent_id: int = None, current_user: schemas.User = Depends(get_current_user),
                        db: crud.Session = Depends(get_db)):
    required_access_level: models.AccessTypeEnum = models.AccessTypeEnum.admin if not parent_id else models.AccessTypeEnum.maintainer
    al: models.AccessTypeEnum = get_access_level(db, user_id=current_user.id, directory_id=parent_id)
    if al < required_access_level:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to add a Directory here",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return crud.directory_add(db, name, parent_id)


@router.delete("/remove_directory/")
async def remove_directory(directory_id: int, current_user: schemas.User = Depends(get_current_user),
                           db: crud.Session = Depends(get_db)):
    required_level = models.AccessTypeEnum.maintainer
    if get_access_level(db, user_id=current_user.id, directory_id=directory_id) < required_level:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to remove this directory",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # directory_db apparently exists if get_access_level got us this far
    directory_db: models.MachineDirectory = crud.directory_get(db, directory_id)
    # but it should not have machines inside
    if len(directory_db.machines) > 0 or len(directory_db.children) > 0:
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail="The directory is not empty!",
            headers={"WWW-Authenticate": "Bearer"},
        )

    crud.directory_remove(db, directory_db.id)


@router.put("/edit_directory_name")
async def edit_machine_directory(directory_id: int, name: str, current_user: schemas.User = Depends(get_current_user),
                                 db: crud.Session = Depends(get_db)):
    required_level = models.AccessTypeEnum.maintainer
    level = get_access_level(db, user_id=current_user.id, directory_id=directory_id)
    if level < required_level:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to add edit this directory",
            headers={"WWW-Authenticate": "Bearer"},
        )

    dir_db: models.MachineDirectory = crud.directory_get(db, directory_id)

    dir_db.name = name
    db.commit()


@router.put("/move_directory")
async def move_machine_directory(directory_id: int, parent_id: int = None,
                                 current_user: schemas.User = Depends(get_current_user),
                                 db: crud.Session = Depends(get_db)):
    if not current_user.is_admin and parent_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to move the directory to the root",
            headers={"WWW-Authenticate": "Bearer"},
        )

    required_level = models.AccessTypeEnum.maintainer
    level_moving: models.AccessTypeEnum = get_access_level(db, current_user.id, directory_id=directory_id)
    level_parent: models.AccessTypeEnum = models.AccessTypeEnum.none
    if parent_id:
        level_parent = get_access_level(db, current_user.id, directory_id=parent_id)
    # the upper resolves for us if either directory is not to be found

    if not current_user.is_admin and (level_moving < required_level or level_parent < required_level):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization for on of the directories",
            headers={"WWW-Authenticate": "Bearer"},
        )

    directory_db: models.MachineDirectory = crud.directory_get(db, directory_id)
    directory_db.parent_id = parent_id
    db.commit()


@router.put("/move_machine_to_directory")
async def move_machine_to_directory(machine_id: int, directory_id: int = None,
                                    current_user: schemas.User = Depends(get_current_user),
                                    db: crud.Session = Depends(get_db)):
    needed_level = models.AccessTypeEnum.maintainer
    new_dir_level = get_access_level(db, user_id=current_user.id, directory_id=directory_id)
    machine_level = get_access_level(db, user_id=current_user.id, directory_id=directory_id)
    # In this case a machine level is at the same an original directory level
    if machine_level < needed_level:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to move this machine",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if new_dir_level < needed_level:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to add to this directory",
            headers={"WWW-Authenticate": "Bearer"},
        )

    machine_db: models.Machine = crud.machine_get(db, machine_id)
    machine_db.directory_id = directory_id
    db.commit()  # awful way to do that but I enjoy it!

