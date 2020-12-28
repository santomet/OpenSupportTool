from fastapi import APIRouter, Depends, Request, BackgroundTasks, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sql_orm import crud, schemas, models
import random, string

from .users import get_current_user
from sql_orm.database import get_db
from helpers import crypto, settings, installer_generator, ssh_authkeys_manager
from routers.machines import get_access_level


# HELPERS -------------------------------------------------


async def request_connection_ssh(machine_id: int, remote_port: int, create_temporary_private_key: bool,
                                 current_user: schemas.User,
                                 db: crud.Session):
    """This function processes the request to open ssh connection"""
    # This one is slightly more demanding, we make it as async
    # First check free port in db:
    used_ports = crud.connections_get_used_ports(db)
    used_ports_list = []
    for mach in used_ports:
        used_ports_list.append(mach.port)
    # get random port from the rest
    ports_to_choose = list(set(settings.PORT_LIST) - set(used_ports_list))
    port = random.choice(ports_to_choose)

    crud.connections_add_request(machine_id, current_user.id, models.ConnectionTypeEnum.ssh_tunnel,
                                 remote_port, port, db)

    if create_temporary_private_key:
        private_key_remote, public_key_ssh_tunnel = await crypto.generate_keypair()


async def request_connection_webrtc():  # TODO
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="This method of tunneling is not implemented yet",
        headers={"WWW-Authenticate": "Bearer"},
    )


# -----------------------------------------------------------------------------------------

router = APIRouter()


@router.post("/request_connection")
async def request_connection(machine_id: int, remote_port: int, connection_type: models.ConnectionTypeEnum,
                             create_temporary_private_key: bool = False,
                             current_user: schemas.User = Depends(get_current_user),
                             db: crud.Session = Depends(get_db)):
    access_level: models.AccessTypeEnum = get_access_level(user_id=current_user.id, machine_id=machine_id, db=db)
    needed_access_level: models.AccessTypeEnum = models.AccessTypeEnum.supporter  # reporter can not connect

    if access_level < needed_access_level:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to do this operation",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Ok, now create the tunnel:

    if connection_type is models.ConnectionTypeEnum.ssh_tunnel:
        return request_connection_ssh(machine_id=machine_id, remote_port=remote_port,
                                      create_temporary_private_key=create_temporary_private_key,
                                      current_user=current_user, db=db)

    elif connection_type is models.ConnectionTypeEnum.webrtc:
        return request_connection_webrtc()
