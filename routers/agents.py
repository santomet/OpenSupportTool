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


# -----------------------------------------------------------------------------------------

router = APIRouter()


@router.get("/query/{agent_token}", response_model=schemas.AgentResponse)
async def agent_query(agent_token: str):
    response = schemas.AgentResponse()
    action = schemas.AgentResponse.Action()
    response.actions.append(action)
    return response

