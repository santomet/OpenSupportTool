import uvicorn
import asyncio
import string
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from routers import machines, users, tunnels, agents

from sql_orm import crud, models, schemas, database
from sql_orm.database import get_db
from helpers import crypto, settings, global_storage, cleaninglady

app = FastAPI(title="Open Support Tool",
              description="Simple tool to control your Linux machines (works with sish ssh server)",
              version="0.1", )

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

models.Base.metadata.create_all(bind=database.engine)
# Check if there are any users in the db and create a default: admin:admin if not
if crud.users_is_empty(get_db().__next__()):
    crud.user_create(get_db().__next__(), schemas.UserCreate(username="admin", password="admin",
                                                             email="mail@example.com", is_admin=True))
    print("No users found in database, administrator admin with password admin created")

# Check if we have generated a password for generating valid tokens
if not crud.tokenpass_get(get_db().__next__()):
    crud.tokenpass_set(get_db().__next__(), crypto.generate_random_standard_hex())
    print("No Tokenpass (password for checking tokens) found in database, creating a new one")

tokenpass_db: models.TokenCheckPassword = crud.tokenpass_get(get_db().__next__())
global_storage.db_token_check_password = tokenpass_db.password
print("Just for debug: Tokenpass: " + global_storage.db_token_check_password)


@app.on_event("startup")
async def startup_event():
    await cleaninglady.start(settings.CLEANING_LADY_INTERVAL_SECONDS)

@app.get("/")
def read_root():
    return {"Message": "Welcome, this is Open Support Tool, see /docs for docs :)"}


app.include_router(
    machines.router,
    prefix="/machines",
    tags=["machines"]
)

app.include_router(
    users.router,
    prefix="/users",
    tags=["users"]
)

app.include_router(
    tunnels.router,
    prefix="/tunnels",
    tags=["tunnels"]
)

app.include_router(
    agents.router,
    prefix="/agents",
    tags=["agents"],
)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)