from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=6)


class UserOut(BaseModel):
    id: int
    username: str
    email: EmailStr
    created_at: datetime

    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    username: str
    password: str


class AuthResponse(BaseModel):
    user: UserOut
    token: str


class RoomCreate(BaseModel):
    name: str = Field(min_length=3, max_length=100)
    video_url: str
    created_by: int
    password: Optional[str] = None


class RoomUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=3, max_length=100)
    video_url: Optional[str] = None
    password: Optional[str] = Field(default=None)


class RoomOut(BaseModel):
    id: int
    slug: str
    name: str
    video_url: str
    is_private: bool
    created_at: datetime
    created_by: int
    participants: List[UserOut]
    playback_position: float
    is_playing: bool
    playback_updated_at: datetime

    class Config:
        from_attributes = True


class JoinRoomRequest(BaseModel):
    user_id: int
    password: Optional[str] = None


class KickRequest(BaseModel):
    username: str


class TransferOwnership(BaseModel):
    requester_id: int
    new_owner_id: int


class MessageOut(BaseModel):
    id: int
    room_id: int
    user: UserOut
    text: str
    created_at: datetime

    class Config:
        from_attributes = True


class MessageCreate(BaseModel):
    user_id: int
    text: str = Field(min_length=1, max_length=1000)


class PlaybackUpdate(BaseModel):
    user_id: int
    position: float
    is_playing: bool
