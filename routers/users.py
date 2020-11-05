from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from helpers import settings

from pydantic import BaseModel
from sql_orm import crud, models, schemas, database
from sql_orm.crud import get_password_hash, verify_password
from sql_orm.database import get_db



# ----------AUTH-----------------------------------------------------------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/login")


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


def authenticate_user(username: str, password: str, db: crud.Session):
    user = crud.user_get_by_username(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme), db: crud.Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = crud.user_get_by_username(db, token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def check_current_user_admin(token: str = Depends(oauth2_scheme), db: crud.Session = Depends(get_db)):
    current_user: schemas.User = await get_current_user(token, db)
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to do this operation",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return current_user

# API-----------------------------------------------------------------------------------------


router = APIRouter()


@router.post("/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: crud.Session = Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/list")
def list_users(db: crud.Session = Depends(get_db),
               current_user: schemas.User = Depends(check_current_user_admin)):
    return crud.users_get(db)


@router.get("/me")
async def read_users_me(current_user: schemas.User = Depends(get_current_user)):
    return current_user


@router.post("/user_create/{username}:{password}:{is_admin}:{email}")
def create_user(username: str, password: str, email: str, is_admin: bool, db: crud.Session = Depends(get_db),
                current_user: schemas.User = Depends(check_current_user_admin)):
    user = schemas.UserCreate(username=username, password=password, email=email, is_admin=is_admin)
    return crud.user_create(db, user)


@router.put("/change_password/{username}:{new_password}")
def change_password(username: str, new_password: str, db: crud.Session = Depends(get_db),
                    current_user: schemas.User = Depends(get_current_user)):
    if current_user.username != username and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to do this operation",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return crud.user_change_password(db, username, new_password)


@router.delete("/user_delete/{username}")
def delete_user(username: str, current_user: schemas.User = Depends(get_current_user), db: crud.Session = Depends(get_db)):
    return crud.user_delete(db, username)



