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


def get_access_level(user_id: int, machine_id: int, db: crud.Session):
    user: models.User = crud.user_get(db, user_id)
    if user.is_admin:
        return models.AccessTypeEnum.owner

    highest_access = models.AccessTypeEnum.none
    # gradually go through groups and machines and get the highest access:
    # First get all the accesses from the user and groups in which the user is
    accesses: [models.Access] = []

    if user.accesses:
        accesses.extend(user.accesses)

    g: models.UserGroup
    if user.groups:
        for g in user.groups:
            accesses.extend(g.accesses)

    # Now check accesses
    a: models.Access
    for a in accesses:
        if a.machine_id and a.machine_id is machine_id:
            if a.type > highest_access:
                highest_access = a.type

        # And also for machine groups:
        if a.machine_group:
            mg: models.MachineGroup = a.machine_group
            m: models.Machine
            for m in mg.machines:
                if m.machine_id is machine_id and a.type > highest_access:
                    highest_access = a.type

    return highest_access


# -----------------------------------------------------------------------------------


@router.get("/list", response_model=List[schemas.MachineDetails])
async def get_machines_list(current_user: schemas.User = Depends(get_current_user), db: crud.Session = Depends(get_db)):
    if current_user.is_admin:
        return crud.machines_get(db)

    machines = []
    for a in current_user.accesses:
        machines.append(a.machine)

    return machines


@router.post("/add_machine/", response_model=schemas.Machine)
async def add_machine(machine: schemas.MachineBase, request: Request, current_user: schemas.User = Depends(get_current_user),
                      db: crud.Session = Depends(get_db)):
    """
    Adds a machine with certain name, description and then returns a whole machine object with generated values
    """
    machine_create = schemas.MachineCreate(**dict(machine))
    # generate random token for downloading the install script
    one_time_installer_token = crypto.generate_provable_token(True)
    machine_create.one_time_installer_token = one_time_installer_token
    # now generate random token for sending stats
    token: str = crypto.generate_provable_token(False)

    machine_full: schemas.Machine = crud.machine_create(db, machine_create, token)
    # now if the current user is not admin, automatically set him as maintainer
    access = schemas.AccessCreate(user_id=current_user.id, machine_id=machine_full.id,
                                  type=models.AccessTypeEnum.owner)
    crud.access_add(db, access)

    # lastly add the url for convenience
    machine_full.one_time_installer_url = ("https://" + str(request.url.hostname) + ":" + str(request.url.port) +
                                           "/machines/installer/" + one_time_installer_token)

    return machine_full


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

    file = await installer_generator.generate_installer_file(machine, request.url.hostname, request.url.port)
    crud.machine_set_new_installer_token(db, machine.id, None)
    background_tasks.add_task(installer_generator.remove_file, file.name)  # this closes file after returning a response
    return FileResponse(path=file.name, filename="installer.sh")


class SishTokenBody(BaseModel):
    pubkey: str
    token: str


@router.post("/set_ssh_auth_key")  # OBSOLETE?
async def set_sish_pubkey(b: SishTokenBody, db: crud.Session = Depends(get_db)):
    machine = crud.machine_get_by_sish_set_token(db, b.token)
    if not machine:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found"
        )
    machine = crud.machine_set_new_sish_public_key(db, machine.id, b.pubkey)

    if not machine:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error, contact developers!"
        )

    success = ssh_authkeys_manager.set_ssh_auth_key(machine.id, b.pubkey, machine.port)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error, contact developers!"
        )

    crud.machine_set_new_sish_set_token(db, machine.id, None)

    return {0}


@router.get("/generate_installer_link/{machine_id}")
async def generate_installer_link(machine_id: int, current_user: schemas.User = Depends(get_current_user),
                                  db: crud.Session = Depends(get_db)):
    access_type = get_access_level(current_user.id, machine_id, db)

    if access_type is not models.AccessTypeEnum.maintainer and access_type is not models.AccessTypeEnum.owner:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to do this operation",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # now generate random token for downloading the install script
    one_time_installer_token = crypto.generate_provable_token(True)

    crud.machine_set_new_installer_token(db, machine_id, one_time_installer_token)

    return {"machine_id": machine_id, "one_time_installer_token": one_time_installer_token}


@router.put("/update_access")
async def update_access(access_type: models.AccessTypeEnum, current_user: schemas.User = Depends(get_current_user),
                        db: crud.Session = Depends(get_db),
                        user_group_id: int = None, user_id: int = None, machine_group_id: int = None,
                        machine_id: int = None):
    # First check whether we have the right combination of inputs: so only one from
    # user_group_id and user_id and only one from machine_id and machine_group_id
    if (bool(user_group_id) is bool(user_id)) or (bool(machine_id) is bool(machine_group_id)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An error occurred (update_access): Incorrect combination of input parameters",
        )

    # Now does the current user have an access that can append other accesses? Only owner can do that!
    # first case: we are creating access for a machine:
    if machine_id:
        if get_access_level(current_user.id, machine_id, db) == models.AccessTypeEnum.owner:
            # remove access if type enum is none
            acc: models.Access = crud.access_get(db, user_id=user_id, machine_id=machine_id,
                                                 machine_group_id=machine_group_id)
            if acc:
                crud.access_delete(db, acc.id)
            if access_type is models.AccessTypeEnum.none:
                return {}

            return crud.access_add(db, schemas.AccessCreate(user_id=user_id, machine_id=machine_id,
                                                            machine_group_id=machine_group_id,
                                                            type=access_type))
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="You do not have authorization to do this operation",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # otherwise if we are dealing with the group
    elif machine_group_id:
        return {}


@router.delete("/delete_machine/{machine_id}")
async def machine_delete(machine_id: int, current_user: schemas.User = Depends(get_current_user),
                         db: crud.Session = Depends(get_db)):
    # First check if user has the right to do that:
    al = get_access_level(current_user.id, machine_id, db)
    if al is not models.AccessTypeEnum.owner:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to do this operation",
            headers={"WWW-Authenticate": "Bearer"},
        )
    ret = crud.machine_delete(db, machine_id)
    if not ret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Machine not found"
        )
    return 0


'''
@router.post("/groups/add_group/{group_name}")
async def create_machine_group(group_name: str, current_user: schemas.User = Depends(get_current_user),
                               db: crud.Session = Depends(get_db)):
    ret = crud.machine_group_create(db, group_name)
    if not ret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred (create_machine_group): Could not add machine group",
        )
    # also create an association with this user
    ret2 = crud.access_add(db, schemas.AccessCreate(user_id=current_user.id, machine_group_id=ret.id,
                                                    type=schemas.AccessTypeEnum.owner))
    if not ret2:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred (create_machine_group): Could not add access to created group",
        )
    return ret


@router.get("/groups/list")
async def machine_groups_list(current_user: schemas.User = Depends(get_current_user),
                              db: crud.Session = Depends(get_db)):
    return crud.machine_groups_list(db)

'''