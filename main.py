from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
import jwt
import hashlib
import urllib.parse
import os

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
username = urllib.parse.quote_plus("malaviyatarun099")
password = urllib.parse.quote_plus("Mt@82786")
MONGODB_URL = f"mongodb+srv://{username}:{password}@cluster0.ygevcay.mongodb.net/"

DATABASE_NAME = "auth_comment_db"

# MongoDB connection
client = AsyncIOMotorClient(MONGODB_URL)
db = client[DATABASE_NAME]
users_collection = db["users"]
comments_collection = db["comments"]

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Models
class UserSignup(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class Comment(BaseModel):
    text: str

# Helper functions
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_token(username: str) -> str:
    exp = datetime.utcnow() + timedelta(days=7)
    return jwt.encode({"username": username, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("username")
    except:
        return None

# Startup and shutdown events
@app.on_event("startup")
async def startup_db():
    # Create indexes
    await users_collection.create_index("username", unique=True)
    await comments_collection.create_index("created_at")

@app.on_event("shutdown")
async def shutdown_db():
    client.close()

# Routes
@app.post("/signup")
async def signup(user: UserSignup):
    # Check if user exists
    existing_user = await users_collection.find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    existing_email = await users_collection.find_one({"email": user.email})
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already exists")
    
    # Hash password and create user
    hashed_pw = hash_password(user.password)
    user_doc = {
        "username": user.username,
        "email": user.email,
        "password": hashed_pw,
        "created_at": datetime.utcnow()
    }
    
    result = await users_collection.insert_one(user_doc)
    
    token = create_token(user.username)
    return {
        "token": token,
        "user": {"username": user.username, "email": user.email}
    }

@app.post("/login")
async def login(user: UserLogin):
    # Find user
    db_user = await users_collection.find_one({"username": user.username})
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Verify password
    hashed_pw = hash_password(user.password)
    if db_user["password"] != hashed_pw:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(user.username)
    return {
        "token": token,
        "user": {"username": db_user["username"], "email": db_user["email"]}
    }

@app.get("/profile")
async def get_profile(token: str = Depends(oauth2_scheme)):
    username = verify_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = await users_collection.find_one({"username": username})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return {"username": user["username"], "email": user["email"]}

@app.get("/comments")
async def get_comments(token: str = Depends(oauth2_scheme)):
    username = verify_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Get all comments sorted by created_at descending
    cursor = comments_collection.find().sort("created_at", -1)
    comments = await cursor.to_list(length=100)
    
    # Convert ObjectId to string
    for comment in comments:
        comment["id"] = str(comment.pop("_id"))
    
    return comments

@app.post("/comments")
async def create_comment(comment: Comment, token: str = Depends(oauth2_scheme)):
    username = verify_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Create comment document
    comment_doc = {
        "username": username,
        "text": comment.text,
        "created_at": datetime.utcnow()
    }
    
    result = await comments_collection.insert_one(comment_doc)
    
    # Return created comment
    new_comment = {
        "id": str(result.inserted_id),
        "username": username,
        "text": comment.text,
        "created_at": comment_doc["created_at"].isoformat()
    }
    
    return new_comment

@app.delete("/comments/{comment_id}")
async def delete_comment(comment_id: str, token: str = Depends(oauth2_scheme)):
    username = verify_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Find comment
    comment = await comments_collection.find_one({"_id": ObjectId(comment_id)})
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    
    # Check if user owns the comment
    if comment["username"] != username:
        raise HTTPException(status_code=403, detail="Not authorized to delete this comment")
    
    await comments_collection.delete_one({"_id": ObjectId(comment_id)})
    return {"message": "Comment deleted successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)