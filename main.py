# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt
from fastapi.middleware.cors import CORSMiddleware

from sql_orm import crud, models, schemas, database
from sql_orm.crud import get_password_hash, verify_password
from sql_orm.database import get_db
import random

random.seed()  # takes system time by default

app = FastAPI(title="Open Support Tool",
    description="Simple tool to control your Linux machines (works with sish ssh server)",
    version="0.1",)


origins = [
    "http://localhost.tiangolo.com",
    "https://localhost.tiangolo.com",
    "http://localhost",
    "http://localhost:8080"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

models.Base.metadata.create_all(bind=database.engine)
if crud.users_is_empty(get_db().__next__()):
    crud.user_create(get_db().__next__(), schemas.UserCreate(username="admin", password="admin",
                                                             email="mail@example.com", is_admin=True))
    print("No users found in database, administrator admin with password admin created")


# Check if there are any users in the db and create a default: admin:admin if not


from routers import machines, users


@app.get("/")
def read_root():
    return {"Message": "Welcome, this is Support Tool", "version": "1.0"}


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




