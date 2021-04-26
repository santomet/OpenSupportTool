from fastapi import APIRouter, Depends, Request, BackgroundTasks, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sql_orm import crud, schemas, models
import random, string
from typing import List
from .users import get_current_user
from sql_orm.database import get_db
from helpers import crypto, settings, installer_generator, ssh_authkeys_manager

import datetime

# HELPERS -------------------------------------------------


# -----------------------------------------------------------------------------------------

router = APIRouter()

""" This is the interface for the agents"""


@router.post("/query", response_model=schemas.AgentResponse)
async def agent_query(agentq: schemas.AgentQuery, db: crud.Session = Depends(get_db)):
    if not crypto.prove_token(agentq.token):
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail="Invalid Token"
        )

    machine_db: models.Machine = crud.machine_get_by_token(db, agentq.token)

    if not machine_db:
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail="Invalid Token"
        )

    # Now save the last keepalive + other stats:
    machine_db.last_query_datetime = datetime.datetime.utcnow()
    machine_db.last_cpu_percent = agentq.last_cpu_percent
    machine_db.last_memory_percent = agentq.last_memory_percent
    # Here we can hypothetically insert calls to some logging mechanisms

    db.commit()  # update directly here :O it works

    machine: schemas.Machine = machine_db
    response = schemas.AgentResponse()
    response.message = ""

    # we are now interested in all the tunnels which are requested to be create terminated
    tunnels: List[schemas.AgentResponse.Tunnel]
    requestedStates: List[models.ConnectionStateEnum] = [models.ConnectionStateEnum.requested,
                                                         models.ConnectionStateEnum.disconnect_requested]
    tunnels = crud.tunnels_list(db, machine.id, requestedStates)
    nonexpired_tunnels = []
    for t in tunnels:
        t.remote_ssh_port = settings.SSH_PORT
        t.remote_ssh_server = settings.SSH_SERVER
        t.remote_ssh_fingerprint = settings.SSH_SERVER_PUBLIC_FINGERPRINT
        t.remote_ssh_username = settings.SSH_SERVER_USERNAME
        if t.timeout_time > datetime.datetime.utcnow():
            nonexpired_tunnels.append(t)
        else:
            t.connection_state = models.ConnectionStateEnum.disconnected
            crud.tunnel_update(db, t)  # fix it! that should not be there
    response.tunnels_requesting_action.extend(nonexpired_tunnels)

    return response


@router.post("/agent_install")
async def agent_install(agentq: schemas.AgentInstall, db: crud.Session = Depends(get_db)):
    if not crypto.prove_token(agentq.token):
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail="Invalid Token"
        )

    machine_db: models.Machine = crud.machine_get_by_token(db, agentq.token)

    if not machine_db:
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail="Invalid Token"
        )

    machine_db.agent_user_name = agentq.agent_user_name
    db.commit()
    # returns 200 automatically

@router.post("/tunnel_changed")
async def set_tunnel_state_connected(agentq: schemas.AgentTunnelChange, background_tasks: BackgroundTasks, db: crud.Session = Depends(get_db)):
    if not crypto.prove_token(agentq.token):
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail="Invalid Token"
        )

    db_tunnel: models.Tunnel = crud.tunnel_get_request_by_id(db, agentq.tunnel_id)
    if not db_tunnel:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tunnel not found"
        )

    if db_tunnel.connection_state is not models.ConnectionStateEnum.requested and agentq.new_state == models.ConnectionStateEnum.connected:
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail="The tunnel is not in the state of being requested"
        )

    if agentq.new_state == models.ConnectionStateEnum.disconnected:
        background_tasks.add_task(ssh_authkeys_manager.remove_particular_ssh_auth_key, db_tunnel.temporary_tunnel_pubkey)

    db_tunnel.connection_state = agentq.new_state
    db_tunnel.remote_ssh_server = agentq.remote_ssh_server
    crud.tunnel_update(db, db_tunnel)


