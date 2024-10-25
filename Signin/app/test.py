from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from twilio.rest import Client
from redis import Redis
from jose import JWTError, jwt
import pyotp
import time


# Azure Redis setup
redis_client = Redis(
    host='rush-rabbit-cache.redis.cache.windows.net',
    port=6380,
    password='xYLxCXUIeP6XswV9AJP7Px89EL58WrPnoAzCaNbaq08=',  # Replace with your Redis primary key
    ssl=True  # Use SSL for Azure Redis
)

redis_client.setex(f"otp:{+4477}", 300, "55")
print('done')