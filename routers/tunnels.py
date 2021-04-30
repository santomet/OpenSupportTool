from fastapi import APIRouter, Depends, Request, BackgroundTasks, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sql_orm import crud, schemas, models
import random, string
from typing import List

from .users import get_current_user
from sql_orm.database import get_db
from helpers import crypto, settings, installer_generator, ssh_authkeys_manager
from routers.machines import get_access_level
import datetime


# HELPERS -------------------------------------------------


async def request_tunnel_ssh(model: schemas.TunnelRequest,
                             current_user: schemas.User,
                             db: crud.Session):
    """This function processes the request to open ssh tunnel"""
    # This one is slightly more demanding, we make it as async
    # First check free reverse port in db. These are the public ports which will be directed to the tunnel:
    used_ports = crud.tunnel_get_used_reverse_ports(db)
    used_ports_list = []
    for mach in used_ports:  # converting from the
        used_ports_list.append(mach.reverse_port)
    ports_to_choose = list(set(settings.PORT_LIST) - set(used_ports_list))
    if len(ports_to_choose) < 1:
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail="We do not have any free ports right now!",
        )

    reverse_port: int = random.choice(ports_to_choose)  # get random port from the rest

    timeout_time = datetime.datetime.utcnow() + datetime.timedelta(seconds=model.timeout_seconds)

    # now we need to create temporary keypair for the reverse tunnel
    # We do it here because we want to be able to make multiple servers and single DB scenario.
    # Everything important is done here and saved to DB, it is then distributed from whichever server
    # and can be served by SSH server that the user specified
    tunnel_private_key, tunnel_public_key = await crypto.generate_keypair()
    success = ssh_authkeys_manager.set_ssh_auth_key(timeout_time, tunnel_public_key, reverse_port)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Keypair could not be added to the ssh server auth_keys",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # create the the blank model for DB and fill what we know
    db_tunnel = models.Tunnel()
    db_tunnel.connection_type = model.connection_type
    db_tunnel.machine_id = model.machine_id
    db_tunnel.user_id = current_user.id
    db_tunnel.connection_state = models.ConnectionStateEnum.requested
    db_tunnel.port_to_tunnel = model.port_to_tunnel
    db_tunnel.creation_time = datetime.datetime.utcnow()
    db_tunnel.timeout_time = timeout_time
    db_tunnel.temporary_pubkey_for_agent_ssh = model.temporary_ssh_pubkey

    db_tunnel.reverse_port = reverse_port
    db_tunnel.temporary_tunnel_privkey = tunnel_private_key
    db_tunnel.temporary_tunnel_pubkey = tunnel_public_key

    # server-specific
    db_tunnel.remote_ssh_server = settings.SSH_SERVER
    db_tunnel.remote_ssh_fingerprint = settings.SSH_SERVER_PUBLIC_FINGERPRINT
    db_tunnel.remote_ssh_username = settings.SSH_SERVER_USERNAME
    db_tunnel.remote_ssh_port = settings.SSH_PORT

    # Create the item in database
    tunnel_id: int = crud.tunnel_add(db, db_tunnel)
    # create response and fill what we know
    response = schemas.TunnelRequestResponse(id=tunnel_id, reverse_port=reverse_port,
                                             port_to_tunnel=model.port_to_tunnel)
    return response


async def request_tunnel_webrtc():  # TODO
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="This method of tunneling is not implemented yet",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def request_tunnel_ssh_destroy(id: int, db: crud.Session):
    tunnel_db: models.Tunnel = crud.tunnel_get_request_by_id(db, id)
    if not tunnel_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The tunnel does not exist"
        )
    if tunnel_db.connection_state == models.ConnectionStateEnum.disconnected:
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail="The tunnel is already disconnected"
        )

    tunnel_db.connection_state = models.ConnectionStateEnum.disconnect_requested
    crud.tunnel_update(db, tunnel_db)

# -----------------------------------------------------------------------------------------

router = APIRouter()


@router.post("/request_tunnel", response_model=schemas.TunnelRequestResponse)
async def request_tunnel(model: schemas.TunnelRequest,
                         current_user: schemas.User = Depends(get_current_user),
                         db: crud.Session = Depends(get_db)):
    """This is how port forwarding tunnels are requested. User has to be at least of a supporter level."""
    access_level: models.AccessTypeEnum = get_access_level(user_id=current_user.id, machine_id=model.machine_id, db=db)
    needed_access_level: models.AccessTypeEnum = models.AccessTypeEnum.supporter  # reporter can not create tunnels

    if access_level < needed_access_level:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to do this operation",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Ok, now create the tunnel:

    if model.connection_type is models.ConnectionTypeEnum.ssh_tunnel:
        return await request_tunnel_ssh(model,
                                        current_user=current_user, db=db)

    elif model.connection_type is models.ConnectionTypeEnum.webrtc:
        return request_tunnel_webrtc()


@router.delete("/destroy_tunnel")
async def destroy_tunnel(id: int, current_user: schemas.User = Depends(get_current_user),
                         db: crud.Session = Depends(get_db)):
    """User has to be at least supporter. If the tunnel is connected, it will be requested to destroy."""
    tunnel_db: models.Tunnel = crud.tunnel_get_request_by_id(db, id)
    if not tunnel_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The tunnel does not exist"
        )
    access_level: models.AccessTypeEnum = get_access_level(user_id=current_user.id, machine_id=tunnel_db.machine_id, db=db)
    needed_access_level: models.AccessTypeEnum = models.AccessTypeEnum.supporter  # reporter can not create tunnels

    if access_level < needed_access_level:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to do this operation",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Ok, now destroy the tunnel:

    await request_tunnel_ssh_destroy(id, db)

@router.post("/list_tunnels_for_machine", response_model=List[schemas.TunnelInfo])
async def get_tunnels(request: schemas.TunnelsListRequest, current_user: schemas.User = Depends(get_current_user),
                          db: crud.Session = Depends(get_db)):
    """Lists all the tunnels of one of the specified states (all of them if none is specified)
    for a particular machine"""
    db_tunnels = crud.tunnels_list(db, request.machine_id, request.connection_states)
    if current_user.is_admin:
        # shortcut for fast response
        return db_tunnels

    tunnels: List[schemas.TunnelInfo] = []
    a: models.Access
    t: models.Tunnel
    for t in db_tunnels:
        if any(a in t.machine.accesses for a in current_user.accesses):  # We do not need to check the access level here
            tunnels.append(t)

    return tunnels


@router.get("/list_all_tunnels", response_model=List[schemas.TunnelInfo])
async def get_all_tunnels(current_user: schemas.User = Depends(get_current_user),
                          db: crud.Session = Depends(get_db)):
    """Lists all the tunnels for all the machines of all the states. Only accessible machines are listed."""
    # access_level: models.AccessTypeEnum = get_access_level(user_id=current_user.id, machine_id=model.machine_id, db=db)
    # needed_access_level: models.AccessTypeEnum = models.AccessTypeEnum.supporter  # reporter can not create
    #
    # if access_level < needed_access_level:
    #     raise HTTPException(
    #         status_code=status.HTTP_401_UNAUTHORIZED,
    #         detail="You do not have authorization to do this operation",
    #         headers={"WWW-Authenticate": "Bearer"},
    #     )
    if current_user.is_admin:
        return crud.tunnels_list(db)

    tunnels: List[schemas.TunnelInfo] = []
    a: models.Access
    for a in current_user.accesses:
        if a.machine.tunnels:
            tunnels.extend(a.machine.tunnels)

    return tunnels

'''
@router.delete("/remove_connection")
async def remove_connection(connection_id: int)
'''
