from typing import List

from core.hashing import Hasher
from core.otp import OTP
from database.models.users import User
from database.repository.users import get_user_by_email
from database.session import get_db
from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from routers.login.forms import LoginForm

from pydantic import BaseModel
import base64
import os
import json

templates = Jinja2Templates(directory="templates")
router = APIRouter(include_in_schema=True)


@router.get("/login/")
def login(request: Request):
    return templates.TemplateResponse("login/login.html", {"request": request})


@router.post("/login/")
async def login(request: Request, db: Session = Depends(get_db)):
    form = LoginForm(request)
    await form.load_data()
    if await form.is_valid():
        try:
            user: User = get_user_by_email(form.email, db=db)
            if user is None or not Hasher.verify_password(form.password, user.hashed_password) or \
                    not OTP.verify_otp(user.secret, form.token):
                form.__dict__.get("errors").append("Incorrect Credentails")
                return templates.TemplateResponse("login/login.html", form.__dict__)

            return templates.TemplateResponse("home/index.html", {"request": request, "email": user.email})
        except HTTPException:
            form.__dict__.update(msg="")
            form.__dict__.get("errors").append("Incorrect Email or Password")
            return templates.TemplateResponse("login/login.html", form.__dict__)
    return templates.TemplateResponse("login/login.html", form.__dict__)


class AppLoginData(BaseModel):
    email: str
    password: str
    token: str
    ip_address: str
    errors: List = []

    async def is_valid(self):
        if not self.email or not (self.email.__contains__("@")):
            self.errors.append("Email is required")
        if not self.password or not len(self.password) >= 4:
            self.errors.append("A valid password is required")
        if len(self.token) != 6:
            self.errors.append("Enter valid token")
        if not self.errors:
            return True
        return False

current_session = {}
contact_list = set()

@router.post('/login_from_app')
async def login_from_app(app_login_data: AppLoginData, db: Session = Depends(get_db)):
    if not await app_login_data.is_valid():
        return {
            'errorCode': -1,
            'msg': app_login_data.errors
        }

    user: User = get_user_by_email(app_login_data.email, db=db)
    if user is None or not Hasher.verify_password(app_login_data.password, user.hashed_password) or \
            not OTP.verify_otp(user.secret, app_login_data.token):
        app_login_data.__dict__.get("errors").append("Incorrect Credentails")
        return {
            'errorCode': -1,
            'msg': app_login_data.errors
        }

    session_id = base64.b32encode(os.urandom(10)).decode('utf-8')
    current_session[app_login_data.email] = session_id
    contact_list.add(json.dumps({
        'email': app_login_data.email,
        'ip_address': app_login_data.ip_address
    }))

    print(current_session)
    return {
        'errorCode': 0,
        'msg': 'Success',
        'session_id': session_id
    }


def make_ret(code, msg):
    return {
        'errorCode': code,
        'msg': msg
    }


def check_session(email, session_id):
    if email not in current_session.keys():
        return False, make_ret(-1, 'not logged in')

    if current_session[email] != session_id:
        return False, make_ret(-1, 'invalid connection')

    return True, {}


@router.get('/contacts')
async def get_contacts(email, session_id):
    check_valid, err = check_session(email, session_id)
    if not check_valid:
        return err

    return make_ret(0, [json.loads(j) for j in contact_list])
