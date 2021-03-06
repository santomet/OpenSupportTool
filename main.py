import uvicorn
import os
from fastapi import FastAPI, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from routers import machines, users, tunnels, agents

from sql_orm import crud, models, schemas, database
from sql_orm.database import get_db
from helpers import crypto, settings, global_storage, cleaninglady


if not os.path.exists(settings.SSH_AUTH_KEYS_FILE_PATH):
    with open(settings.SSH_AUTH_KEYS_FILE_PATH, 'w'): pass

app = FastAPI(title="Open Support Tool",
              description="Simple API for remote management: Port forwarding on-demand, user accounts and access levels."
                          "\nThe Wiki can be found on the github repo.",
              version="0.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

models.Base.metadata.create_all(bind=database.engine)

# Check if we have generated a password for generating valid tokens
if not crud.tokenpass_get(get_db().__next__()):
    crud.tokenpass_set(get_db().__next__(), crypto.generate_random_standard_hex())
    print("No Tokenpass (password for checking tokens) found in database, creating a new one")

tokenpass_db: models.TokenCheckPassword = crud.tokenpass_get(get_db().__next__())
global_storage.db_token_check_password = tokenpass_db.password
print("Just for debug: Tokenpass: " + global_storage.db_token_check_password)

# Check if we have generated a password for JWT
if not crud.jwtpass_get(get_db().__next__()):
    crud.jwtpass_set(get_db().__next__(), crypto.generate_random_custom_hex(32))
    print("No JWT secret (secret for generating JWT tokens) found in database, creating a new one")

jwtpass_db: models.TokenCheckPassword = crud.jwtpass_get(get_db().__next__())
global_storage.db_jwt_secret_password = jwtpass_db.password
print("Just for debug: JWT SECRET: " + global_storage.db_jwt_secret_password)

# Check if there are any users in the db and create a default: admin:admin if not
if crud.users_is_empty(get_db().__next__()):
    crud.user_create(get_db().__next__(), schemas.UserCreate(username="admin", password="admin",
                                                             email="mail@example.com", is_admin=True))
    print("No users found in database, administrator admin with password admin created")


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


@app.get("/{one_time_installer_token}")
async def get_installer(one_time_installer_token: str, request: Request, background_tasks: BackgroundTasks,
                        db: crud.Session = Depends(get_db)):
    return await machines.download_installer(one_time_installer_token, request, background_tasks, db)


if __name__ == "__main__":
    conf = {"host": "0.0.0.0", "port": settings.API_PORT}
    if not settings.TEST_MODE:
        conf["ssl_certfile"] = settings.SSL_CERT_LOCATION
        conf["ssl_keyfile"] = settings.SSL_KEY_LOCATION
        conf["ssl_ca_certs"] = settings.SSL_CA_LOCATION

    uvicorn.run(app, **conf)
