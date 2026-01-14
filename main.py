from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
import jwt
import hashlib
import os
import urllib.parse
import logging
import asyncio

# ------------------ Logging (very useful when debugging) ------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ------------------ APP ------------------
app = FastAPI(title="RunMyTools API", version="1.0")

# ------------------ CORS ------------------
# In production → replace "*" with your actual frontend domain(s)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------ CONFIG ------------------
SECRET_KEY = os.getenv("SECRET_KEY") or "super-secret-change-me-in-production-2025"
if SECRET_KEY == "super-secret-change-me-in-production-2025":
    logger.warning("Using insecure default SECRET_KEY – set REAL SECRET_KEY env variable!")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 7

# MongoDB connection
username = urllib.parse.quote_plus("malaviyatarun099")
password = urllib.parse.quote_plus("Mt@82786")
MONGODB_URL = f"mongodb+srv://{username}:{password}@cluster0.ygevcay.mongodb.net/?retryWrites=true&w=majority"

DATABASE_NAME = "auth_comment_db"

# ------------------ DB ------------------
client = AsyncIOMotorClient(MONGODB_URL)
db = client[DATABASE_NAME]
users_collection = db["users"]
comments_collection = db["comments"]

# ------------------ AUTH ------------------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# ------------------ MODELS ------------------
class UserSignup(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str = None
    email: str = None
    password: str

class CommentCreate(BaseModel):
    content: str
    toolId: str

# ------------------ UTILS ------------------
def hash_password(password: str):
    return hashlib.sha256(password.encode()).hexdigest()

def create_token(username: str):
    payload = {
        "sub": username,           # more standard than "username"
        "exp": datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_username(token: str = Depends(oauth2_scheme)):
    try:
        if not token:
            raise HTTPException(status_code=401, detail="Not authenticated")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token error: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        raise HTTPException(status_code=401, detail="Authentication failed")

# ------------------ BACKGROUND TASKS ------------------
async def delete_old_comments():
    """Delete comments older than 48 hours"""
    while True:
        try:
            # Calculate the cutoff time (48 hours ago)
            cutoff_time = datetime.utcnow() - timedelta(hours=48)
            
            # Delete comments older than 48 hours
            result = await comments_collection.delete_many({
                "created_at": {"$lt": cutoff_time}
            })
            
            if result.deleted_count > 0:
                logger.info(f"Deleted {result.deleted_count} comment(s) older than 48 hours")
            
            # Run this task every hour
            await asyncio.sleep(3600)  # 3600 seconds = 1 hour
        except Exception as e:
            logger.error(f"Error in delete_old_comments task: {e}")
            # If there's an error, wait 1 hour before retrying
            await asyncio.sleep(3600)

# ------------------ STARTUP ------------------
@app.on_event("startup")
async def startup_event():
    try:
        # Create indexes (idempotent)
        await users_collection.create_index("username", unique=True)
        await users_collection.create_index("email", unique=True)
        await comments_collection.create_index([("toolId", 1), ("created_at", -1)])
        await comments_collection.create_index("created_at", -1)
        logger.info("MongoDB indexes created / verified")
        
        # Start background task to delete old comments
        asyncio.create_task(delete_old_comments())
        logger.info("Background task started: Auto-delete comments older than 48 hours")
    except Exception as e:
        logger.error(f"Error in startup: {e}")

# ------------------ AUTH ROUTES ------------------
@app.post("/signup", response_model_exclude_unset=True)
async def signup(user: UserSignup):
    try:
        if await users_collection.find_one({"username": user.username}):
            raise HTTPException(400, "Username already exists")

        if await users_collection.find_one({"email": user.email}):
            raise HTTPException(400, "Email already exists")

        user_doc = {
            "username": user.username,
            "email": user.email,
            "password": hash_password(user.password),
            "created_at": datetime.utcnow()
        }

        await users_collection.insert_one(user_doc)
        token = create_token(user.username)

        return {
            "token": token,
            "user": {
                "username": user.username,
                "email": user.email
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in signup: {e}")
        raise HTTPException(500, f"Internal server error: {str(e)}")

@app.post("/login")
async def login(user: UserLogin):
    try:
        # Support both username and email login
        if user.username:
            db_user = await users_collection.find_one({"username": user.username})
        elif user.email:
            db_user = await users_collection.find_one({"email": user.email})
        else:
            raise HTTPException(400, "Either username or email must be provided")
        
        if not db_user or db_user["password"] != hash_password(user.password):
            raise HTTPException(401, "Invalid username/email or password")

        token = create_token(db_user["username"])

        return {
            "token": token,
            "user": {
                "username": db_user["username"],
                "email": db_user["email"]
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in login: {e}")
        raise HTTPException(500, f"Internal server error: {str(e)}")

@app.get("/profile")
async def get_profile(current_user: str = Depends(get_current_username)):
    try:
        user = await users_collection.find_one({"username": current_user})
        if not user:
            raise HTTPException(404, "User not found")

        return {
            "username": user["username"],
            "email": user["email"]
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_profile: {e}")
        raise HTTPException(500, f"Internal server error: {str(e)}")

# ------------------ COMMENTS ------------------
@app.get("/comments")
async def get_comments():
    try:
        # Use find() with sort and limit, then convert to list
        cursor = comments_collection.find().sort("created_at", -1).limit(200)
        docs = await cursor.to_list(length=200)

        result = []
        for doc in docs:
            try:
                created = doc.get("created_at")
                # Handle different datetime formats
                if created is None:
                    created_iso = None
                elif isinstance(created, datetime):
                    created_iso = created.isoformat()
                elif isinstance(created, str):
                    # If it's already a string, try to parse it
                    try:
                        dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                        created_iso = dt.isoformat()
                    except:
                        created_iso = created
                else:
                    created_iso = None

                result.append({
                    "id": str(doc.get("_id", "")),
                    "username": doc.get("username", "Anonymous"),
                    "toolId": doc.get("toolId", ""),
                    "content": doc.get("content", ""),
                    "createdAt": created_iso
                })
            except Exception as e:
                logger.warning(f"Error processing comment {doc.get('_id')}: {e}")
                # Skip malformed comments but continue processing
                continue

        return result
    except Exception as e:
        logger.error(f"Error in get_comments: {e}", exc_info=True)
        raise HTTPException(500, f"Internal server error: {str(e)}")

@app.post("/comments")
async def post_comment(
    comment: CommentCreate,
    current_user: str = Depends(get_current_username)
):
    try:
        if not comment.content or not comment.content.strip():
            raise HTTPException(400, "Comment content cannot be empty")

        if not comment.toolId or not comment.toolId.strip():
            raise HTTPException(400, "Tool ID cannot be empty")

        comment_doc = {
            "username": current_user,           # always from token – never trust client
            "toolId": comment.toolId.strip(),
            "content": comment.content.strip(),
            "created_at": datetime.utcnow()
        }

        result = await comments_collection.insert_one(comment_doc)

        return {
            "id": str(result.inserted_id),
            "username": current_user,
            "toolId": comment.toolId,
            "content": comment.content,
            "createdAt": comment_doc["created_at"].isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in post_comment: {e}", exc_info=True)
        raise HTTPException(500, f"Internal server error: {str(e)}")

@app.delete("/comments/{comment_id}")
async def delete_comment(
    comment_id: str,
    current_user: str = Depends(get_current_username)
):
    try:
        try:
            obj_id = ObjectId(comment_id)
        except:
            raise HTTPException(400, "Invalid comment ID format")

        comment = await comments_collection.find_one({"_id": obj_id})
        if not comment:
            raise HTTPException(404, "Comment not found")

        if comment.get("username") != current_user:
            raise HTTPException(403, "You can only delete your own comments")

        await comments_collection.delete_one({"_id": obj_id})

        return {"message": "Comment deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in delete_comment: {e}", exc_info=True)
        raise HTTPException(500, f"Internal server error: {str(e)}")

# Optional: simple health check
@app.get("/health")
async def health_check():
    try:
        # Test database connection
        await db.command("ping")
        return {"status": "ok", "database": "connected"}
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {"status": "error", "database": "disconnected", "error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, log_level="info")
