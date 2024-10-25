from fastapi import FastAPI, Depends, HTTPException, status, Header, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import JWTError, jwt
from twilio.rest import Client
from redis import Redis
import pyotp
import time

app = FastAPI()

# Define the Bearer token scheme for Swagger
bearer_scheme = HTTPBearer()

# Twilio setup (replace with your Twilio credentials)
account_sid = 'AC491098f4e6cc840518cee1118192da2f'
auth_token = '131cd8e09f03d183154dfc32b08b0840'
twilio_client = Client(account_sid, auth_token)

# Azure Redis setup
redis_client = Redis(
    host='rush-rabbit-cache.redis.cache.windows.net',
    port=6380,
    password='xYLxCXUIeP6XswV9AJP7Px89EL58WrPnoAzCaNbaq08=',  # Replace with your Redis primary key
    ssl=True  # Use SSL for Azure Redis
)

# JWT Secret key and settings
SECRET_KEY = "your_jwt_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Helper functions for OTP and JWT
def generate_otp(phone_number: str):
    otp_secret = pyotp.random_base32()
    totp = pyotp.TOTP(otp_secret)
    otp = totp.now()
    redis_client.setex(f"otp:{phone_number}", 300, otp)
    return otp

def send_otp(phone_number: str):
    otp = generate_otp(phone_number)
    twilio_client.messages.create(
        from_='+447412892262',
        body=f"Your OTP is {otp}",
        to=phone_number
    )
    print(f"OTP sent: {otp}")

def verify_otp(phone_number: str, otp: str):
    stored_otp = redis_client.get(f"otp:{phone_number}")
    if stored_otp and stored_otp.decode() == otp:
        redis_client.delete(f"otp:{phone_number}")
        return True
    return False

def create_jwt_token(phone_number: str):
    expire = time.time() + (ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    payload = {"sub": phone_number, "exp": expire}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

# Data models
class OTPRequest(BaseModel):
    phone_number: str

class OTPVerifyRequest(BaseModel):
    phone_number: str
    otp: str

class ProtectedData(BaseModel):
    data: str

# Custom dependency for extracting and verifying JWT from Authorization header
def get_current_user(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        phone_number = payload.get("sub")
        if phone_number is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )
        return phone_number
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

# Routes
@app.post("/request-otp")
def request_otp(otp_request: OTPRequest):
    send_otp(otp_request.phone_number)
    return {"message": "OTP sent successfully"}

@app.post("/verify-otp")
def verify_otp_endpoint(otp_verify_request: OTPVerifyRequest):
    if verify_otp(otp_verify_request.phone_number, otp_verify_request.otp):
        token = create_jwt_token(otp_verify_request.phone_number)
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid OTP"
    )

@app.get("/protected-data", response_model=ProtectedData)
def get_protected_data(current_user: str = Depends(get_current_user)):
    return ProtectedData(data=f"This is protected data for {current_user}")
