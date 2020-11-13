from fastapi import APIRouter, Depends, Request, BackgroundTasks, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sql_orm import crud, schemas, models
import random, string

from .users import get_current_user
from sql_orm.database import get_db
from helpers import crypto, settings, installer_generator, sish_pubkey_manager

router = APIRouter()


# HELPERS ---------------------------------------------------------------------------

# TODO EXTEND THIS :) <3
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


@router.get("/list")
async def get_machines_list(current_user: schemas.User = Depends(get_current_user), db: crud.Session = Depends(get_db)):
    if current_user.is_admin:
        return crud.machines_get(db)

    machines = []
    for a in current_user.accesses:
        machines.append(a.machine)

    return machines


@router.post("/add_machine/{title}", )
async def add_machine(title: str, current_user: schemas.User = Depends(get_current_user),
                      db: crud.Session = Depends(get_db)):
    # This one is slightly more demanding, we make it as async
    # First check free port in db:
    used_ports = crud.machines_get_used_ports(db)
    used_ports_list = []
    for mach in used_ports:
        used_ports_list.append(mach.port)
    # get random port from the rest
    ports_to_choose = list(set(settings.PORT_LIST) - set(used_ports_list))
    port = random.choice(ports_to_choose)

    # now generate keypair (
    private_key_remote, public_key_remote = await crypto.generate_keypair()

    # now generate random token that will be used when setting the public key from remote computer
    one_time_sish_set_token = "".join(random.choices(string.ascii_letters + string.digits + "+/", k=50))

    # now generate random token for downloading the install script
    one_time_installer_token = "".join(random.choices(string.ascii_uppercase + string.digits, k=5))

    # now generate random token for sending stats

    stats_identifier = "".join(random.choices(string.ascii_letters + string.digits + "+/", k=50))

    # finally create the machine:
    machine = schemas.MachineCreate(title=title, port=port, private_key_remote=private_key_remote,
                                    public_key_remote=public_key_remote,
                                    one_time_sish_set_token=one_time_sish_set_token,
                                    one_time_installer_token=one_time_installer_token,
                                    stats_identifier=stats_identifier)
    machine = crud.machine_create(db, machine)

    # now if the current user is not admin, automatically set him as maintainer

    access = schemas.AccessCreate(user_id=current_user.id, machine_id=machine.id,
                                  type=models.AccessTypeEnum.owner)
    crud.access_add(db, access)

    return {"machine_id": machine.id, "one_time_installer_token": one_time_installer_token}


@router.get("/installer/{one_time_installer_token}")  # NO AUTH!!!!
async def download_installer(one_time_installer_token: str, request: Request, background_tasks: BackgroundTasks,
                             db: crud.Session = Depends(get_db)):
    machine = crud.machine_get_by_installer_token(db, one_time_installer_token)
    if not machine:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found"
        )
    file = await installer_generator.generate_installer_file(machine, request.url.hostname, request.url.port,
                                                             machine.port)
    crud.machine_set_new_installer_token(db, machine.id, None)
    background_tasks.add_task(installer_generator.remove_file, file.name)  # this closes file after returning a response
    return FileResponse(path=file.name, filename="installer.sh")


class SishTokenBody(BaseModel):
    pubkey: str
    token: str


@router.post("/set_sish_pubkey")
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

    success = sish_pubkey_manager.set_sish_pubkey(machine.id, b.pubkey)

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

    # now generate random token that will be used when setting the public key from remote computer
    one_time_sish_set_token = "".join(random.choices(string.ascii_letters + string.digits + "+/", k=50))

    # now generate random token for downloading the install script
    one_time_installer_token = "".join(random.choices(string.ascii_uppercase + string.digits, k=5))

    crud.machine_set_new_installer_token(db, machine_id, one_time_installer_token)
    crud.machine_set_new_sish_set_token(db, machine_id, one_time_sish_set_token)

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