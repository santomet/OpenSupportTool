from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from helpers import settings, global_storage

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
    encoded_jwt = jwt.encode(to_encode, global_storage.db_jwt_secret_password, algorithm=settings.ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme), db: crud.Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, global_storage.db_jwt_secret_password, algorithms=[settings.ALGORITHM])
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
    current_user: schemas.User = get_current_user(token, db)
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


@router.get("/find_user")
async def find_user(username: str = None, email: str = None, db: crud.Session = Depends(get_db),
                    current_user: schemas.User = Depends(get_current_user)):
    # for this any user can be logged in. This is so that I can allow other non-admin users to control my machines
    if bool(username) is bool(email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An error occurred (update_access): Incorrect combination of input parameters",
        )

    ret = None
    if username:
        ret = crud.user_get_by_username(db, username)

    elif email:
        ret = crud.user_get_by_email(db, email)

    if not ret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Such user not found",
        )

    return ret


@router.get("/list")
def list_users(db: crud.Session = Depends(get_db),
               current_user: schemas.User = Depends(check_current_user_admin)):
    return crud.users_get(db)


@router.get("/me")
async def read_users_me(current_user: schemas.User = Depends(get_current_user)):
    return current_user


@router.post("/user_create")
async def create_user(username: str, password: str, email: str, is_admin: bool, db: crud.Session = Depends(get_db),
                      current_user: schemas.User = Depends(check_current_user_admin)):
    user = schemas.UserCreate(username=username, password=password, email=email, is_admin=is_admin)
    return crud.user_create(db, user)


@router.put("/change_password")
async def change_password(username: str, new_password: str, db: crud.Session = Depends(get_db),
                          current_user: schemas.User = Depends(get_current_user)):
    if current_user.username != username and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to do this operation",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return crud.user_change_password(db, username, new_password)


@router.delete("/user_delete")
async def delete_user(username: str, current_user: schemas.User = Depends(get_current_user),
                      db: crud.Session = Depends(get_db)):
    return crud.user_delete(db, username)


@router.get("/user_group_list", response_model=List[schemas.UserGroup])
async def router_group_list(current_user: schemas.User = Depends(get_current_user),
                      db: crud.Session = Depends(get_db)):
    if current_user.is_admin:
        return crud.user_group_list(db)

    return current_user.groups


# User Groups - Only admins can work with that
@router.put("/user_group_create")
async def create_user_group(name: str, db: crud.Session = Depends(get_db),
                            current_user: schemas.User = Depends(check_current_user_admin)):
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to do this operation",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return crud.user_group_create(db, name)


@router.delete("/user_group_delete")
async def delete_user_group(ug_id: int, db: crud.Session = Depends(get_db),
                            current_user: schemas.User = Depends(check_current_user_admin)):
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to do this operation",
            headers={"WWW-Authenticate": "Bearer"},
        )

    ret = crud.user_group_delete(db, ug_id)

    if not ret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User group not found",
        )


@router.put("/add_user_to_group")
async def add_user_to_group(user_id: int, group_id: int, db: crud.Session = Depends(get_db),
                            current_user: schemas.User = Depends(check_current_user_admin)):
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to do this operation",
            headers={"WWW-Authenticate": "Bearer"},
        )

    crud.user_add_to_group(db, group_id, user_id)


@router.put("/remove_user_from_group")
async def remove_user_from_group(user_id: int, group_id: int, db: crud.Session = Depends(get_db),
                            current_user: schemas.User = Depends(check_current_user_admin)):

    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to do this operation",
            headers={"WWW-Authenticate": "Bearer"},
        )

    crud.user_remove_from_group(db, group_id, user_id)

# Accesses
@router.put("/update_access")
async def update_access(group_id: int, directory_id: int, level: models.AccessTypeEnum, db: crud.Session = Depends(get_db),
                            current_user: schemas.User = Depends(check_current_user_admin)):
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You do not have authorization to do this operation",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if level > models.AccessTypeEnum.maintainer:
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail="You can not use create any higher access than maintainer. Consider a different approach."
        )

    group_db: models.UserGroup = crud.user_group_get(db, group_id)
    directory_db: models.MachineDirectory = crud.directory_get(db, directory_id)

    if not group_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The user group has not been found"
        )

    if not directory_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The directory has not been found"
        )

    # Now there are some restrictions: At all times one group can only have one path of access to a directory.
    # We first need all the directories IDs from the accessess
    a: models.Access
    adirids = []
    for a in group_db.accesses:
        adirids.append(a.machine_directory_id)


    if directory_id in adirids:
        # let's just update that, shall we?
        access_db: models.Access = crud.access_get(db, machine_directory_id=directory_id, user_group_id=group_id)
        if level == 0:
            crud.access_delete(db, access_db.id)
        else:
            access_db.type = level
            db.commit()
        return

    else:
        # First see if the directory we are looking for is not a descendant of one of the dirs already in accessess
        # This is not allowed at all!
        d: models.MachineDirectory = directory_db
        while d.parent:
            if d.parent_id in adirids:
                raise HTTPException(
                    status_code=status.HTTP_406_NOT_ACCEPTABLE,
                    detail="There already is an implicit access for this group and directory from the directory {}. If you "
                           "need to change the explicit access for this directory and group, please consider different "
                           "directory and group management instead ".format(d.parent.name)
                )
            d = d.parent

        # Ok so it is not a descendant of existing access if we got here
        # Now in case that the old access is some descendant of new one, we will just remove them
        overriden = False
        accessess_to_delete = []
        ad: models.MachineDirectory
        for a in group_db.accesses:
            ad = a.directory
            while ad.parent_id:
                if ad.parent_id is directory_id:
                    overriden = True
                    accessess_to_delete.append(a)
                ad = ad.parent
        for a in accessess_to_delete:
            crud.access_delete(db, a.id)

        # Now we can finally add the access
        if level > 0:
            newac = schemas.Access(type=level, user_group_id=group_id, machine_directory_id=directory_id)
            crud.access_add(db, newac)

        if overriden:
            return {"detail": "Original child accessess has been removed!"}
