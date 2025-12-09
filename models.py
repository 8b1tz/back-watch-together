from datetime import datetime
from typing import Optional
import hashlib
import uuid

from passlib.hash import pbkdf2_sha256
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Table, Float
from sqlalchemy.orm import relationship, Mapped, mapped_column

from database import Base


def legacy_hash_password(password: str) -> str:
    """SHA256 legacy hash (apenas para compatibilidade)."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    # PBKDF2 sem limite curto de tamanho
    return pbkdf2_sha256.hash(password)


room_participants = Table(
    "room_participants",
    Base.metadata,
    Column("room_id", ForeignKey("rooms.id"), primary_key=True),
    Column("user_id", ForeignKey("users.id"), primary_key=True),
    Column("joined_at", DateTime, default=datetime.utcnow),
)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    rooms = relationship("Room", back_populates="creator")
    joined_rooms = relationship(
        "Room",
        secondary=room_participants,
        back_populates="participants",
    )

    def verify_password(self, password: str) -> bool:
        # Suporta: pbkdf2 (atual) e SHA256 legado (bcrypt removido por problema de lib)
        try:
            if self.password_hash.startswith("$pbkdf2-sha256$"):
                return pbkdf2_sha256.verify(password, self.password_hash)
            return self.password_hash == legacy_hash_password(password)
        except Exception:
            return False


class Room(Base):
    __tablename__ = "rooms"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), index=True)
    video_url: Mapped[str] = mapped_column(String(500))
    password_hash: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    is_private: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    playback_position: Mapped[float] = mapped_column(Float, default=0.0)
    is_playing: Mapped[bool] = mapped_column(Boolean, default=False)
    playback_updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=lambda: str(uuid.uuid4()))

    creator = relationship("User", back_populates="rooms")
    participants = relationship(
        "User",
        secondary=room_participants,
        back_populates="joined_rooms",
    )

    def set_password(self, password: Optional[str]) -> None:
        if password:
            self.password_hash = hash_password(password)
            self.is_private = True
        else:
            self.password_hash = None
            self.is_private = False

    def verify_password(self, password: Optional[str]) -> bool:
        if self.password_hash is None:
            return True
        if password is None:
            return False
        try:
            if self.password_hash.startswith("$pbkdf2-sha256$"):
                return pbkdf2_sha256.verify(password, self.password_hash)
            return False
        except Exception:
            return False


class RoomBan(Base):
    __tablename__ = "room_bans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    room_id: Mapped[int] = mapped_column(Integer, ForeignKey("rooms.id"), index=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), index=True)
    banned_until: Mapped[datetime] = mapped_column(DateTime, index=True)


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    room_id: Mapped[int] = mapped_column(Integer, ForeignKey("rooms.id"), index=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    text: Mapped[str] = mapped_column(String(1000))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user = relationship("User")
    room = relationship("Room")
