from datetime import datetime
from typing import Dict, List

import asyncio
import os
from datetime import datetime, timedelta
import jwt
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
import threading

from . import models, schemas
from .database import Base, engine, get_db, SessionLocal

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Video Sharing Platform API", version="0.1.0")

default_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
    "http://localhost:8000",
    "https://magical-frangollo-2c217a.netlify.app",
]
allow_origins = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", ",".join(default_origins)).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Estado em memoria para WebSocket (playback)
room_connections: Dict[int, List[WebSocket]] = {}
room_playback_state: Dict[int, dict] = {}  # room_id -> {video_url, position, is_playing, updated_at}
empty_room_timers: Dict[int, threading.Timer] = {}
EMPTY_GRACE_SECONDS = 60
security = HTTPBearer(auto_error=True)
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-prod")
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "1440"))


def _now_iso() -> str:
    # ISO em UTC com milissegundos e sufixo Z, legivel para JS Date
    return datetime.utcnow().isoformat(timespec="milliseconds") + "Z"


def _ensure_room_state(room: models.Room):
    if room.id not in room_playback_state:
        room_playback_state[room.id] = {
            "video_url": room.video_url,
            "position": room.playback_position or 0.0,
            "is_playing": room.is_playing or False,
            "updated_at": room.playback_updated_at.isoformat(timespec="milliseconds") + "Z"
            if room.playback_updated_at
            else _now_iso(),
        }


def _add_system_message(db: Session, room_id: int, user: models.User, text: str) -> None:
    """Cria uma mensagem de sistema associada ao usuario informado."""
    msg = models.Message(room_id=room_id, user_id=user.id, text=text)
    db.add(msg)
    db.commit()
    db.refresh(msg)


def _cleanup_empty_rooms(db: Session) -> None:
    empties = db.query(models.Room).filter(~models.Room.participants.any()).all()
    for room in empties:
        _delete_room(db, room)


def _delete_room(db: Session, room: models.Room) -> None:
    db.query(models.Message).filter(models.Message.room_id == room.id).delete()
    db.delete(room)
    db.commit()
    room_connections.pop(room.id, None)
    room_playback_state.pop(room.id, None)
    timer = empty_room_timers.pop(room.id, None)
    if timer:
        timer.cancel()


def create_access_token(user: models.User) -> str:
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> models.User:
    token = credentials.credentials
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = int(data.get("sub"))
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = db.get(models.User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return user


async def _broadcast(room_id: int, message: dict):
    conns = room_connections.get(room_id, [])
    living = []
    for ws in conns:
        try:
            await ws.send_json(message)
            living.append(ws)
        except Exception:
            # drop dead connections
            continue
    room_connections[room_id] = living


@app.post("/auth/register", response_model=schemas.AuthResponse)
def register(user_in: schemas.UserCreate, db: Session = Depends(get_db)):
    existing = (
        db.query(models.User)
        .filter(
            (models.User.email == user_in.email) | (models.User.username == user_in.username)
        )
        .first()
    )
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")

    user = models.User(
        username=user_in.username,
        email=user_in.email,
        password_hash=models.hash_password(user_in.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_access_token(user)
    return {"user": user, "token": token}


@app.post("/auth/login", response_model=schemas.AuthResponse)
def login(user_in: schemas.UserLogin, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == user_in.username).first()
    if not user or not user.verify_password(user_in.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token(user)
    return {"user": user, "token": token}


@app.get("/rooms", response_model=List[schemas.RoomOut])
def list_rooms(db: Session = Depends(get_db)):
    _cleanup_empty_rooms(db)
    return db.query(models.Room).filter(models.Room.participants.any()).all()


@app.post("/rooms", response_model=schemas.RoomOut, status_code=status.HTTP_201_CREATED)
def create_room(room_in: schemas.RoomCreate, db: Session = Depends(get_db)):
    creator = db.get(models.User, room_in.created_by)
    if not creator:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Creator not found")

    room = models.Room(
        name=room_in.name,
        video_url=room_in.video_url,
        created_by=creator.id,
    )
    room.set_password(room_in.password)
    room.participants.append(creator)
    db.add(room)
    db.commit()
    db.refresh(room)
    # garante que timers antigos (improvaveis) sejam cancelados
    timer = empty_room_timers.pop(room.id, None)
    if timer:
        timer.cancel()
    _cleanup_empty_rooms(db)
    _ensure_room_state(room)
    return room


@app.get("/rooms/{room_id}", response_model=schemas.RoomOut)
def get_room(room_id: int, db: Session = Depends(get_db)):
    room = db.get(models.Room, room_id)
    if not room:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")
    _ensure_room_state(room)
    return room


@app.patch("/rooms/{room_id}", response_model=schemas.RoomOut)
def update_room(room_id: int, room_in: schemas.RoomUpdate, db: Session = Depends(get_db)):
    room = db.get(models.Room, room_id)
    if not room:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")

    if room_in.name is not None:
        room.name = room_in.name
    if room_in.video_url is not None:
        room.video_url = room_in.video_url
    if room_in.password is not None:
        room.set_password(room_in.password)

    db.commit()
    db.refresh(room)
    _ensure_room_state(room)
    # Notificar video atualizado
    room_playback_state[room.id]["video_url"] = room.video_url
    return room


@app.delete("/rooms/{room_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_room(room_id: int, db: Session = Depends(get_db)):
    room = db.get(models.Room, room_id)
    if not room:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")

    _delete_room(db, room)
    return None


@app.post("/rooms/{room_id}/join", response_model=schemas.RoomOut)
def join_room(room_id: int, join_req: schemas.JoinRoomRequest, db: Session = Depends(get_db)):
    room = db.get(models.Room, room_id)
    if not room:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")

    user = db.get(models.User, join_req.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not room.verify_password(join_req.password):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid room password")

    # cancel deletion timer if any
    timer = empty_room_timers.pop(room_id, None)
    if timer:
        timer.cancel()

    if user not in room.participants:
        room.participants.append(user)
        db.commit()
        db.refresh(room)
        _add_system_message(db, room.id, user, f"{user.username} entrou na sala")
        _cleanup_empty_rooms(db)
    _ensure_room_state(room)
    return room


@app.post("/rooms/{room_id}/leave", response_model=schemas.RoomOut)
def leave_room(room_id: int, join_req: schemas.JoinRoomRequest, db: Session = Depends(get_db)):
    room = db.get(models.Room, room_id)
    if not room:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")

    user = db.get(models.User, join_req.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    removed = False
    if user in room.participants:
        room.participants.remove(user)
        removed = True
        # se criador sair, transfere para outro participante
        if room.created_by == user.id and room.participants:
            room.created_by = room.participants[0].id
        db.commit()
        db.refresh(room)
        _add_system_message(db, room.id, user, f"{user.username} saiu da sala")

    # se sala ficar vazia (apos remover alguÃ©m), agenda exclusao em 2 minutos
    if removed and not room.participants:
        def delete_room_later():
            with SessionLocal() as bg_db:
                stale = bg_db.get(models.Room, room_id)
                if stale and not stale.participants:
                    bg_db.delete(stale)
                    bg_db.commit()
            empty_room_timers.pop(room_id, None)

        timer = threading.Timer(float(EMPTY_GRACE_SECONDS), delete_room_later)
        empty_room_timers[room_id] = timer
        timer.start()

    return room


@app.post("/rooms/{room_id}/kick", response_model=schemas.RoomOut)
def kick_participant(room_id: int, kick: schemas.KickRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    room = db.get(models.Room, room_id)
    if not room:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")

    user = db.query(models.User).filter(models.User.username == kick.username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user in room.participants:
        room.participants.remove(user)
        db.commit()
        db.refresh(room)
        # Notifica user expulso via WebSocket
        background_tasks.add_task(_broadcast, room_id, {"type": "kicked", "user_id": user.id})
        _add_system_message(db, room.id, user, f"{user.username} foi expulso da sala")
    return room


@app.post("/rooms/{room_id}/transfer", response_model=schemas.RoomOut)
def transfer_ownership(room_id: int, transfer: schemas.TransferOwnership, db: Session = Depends(get_db)):
    room = db.get(models.Room, room_id)
    if not room:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")

    if room.created_by != transfer.requester_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only current owner can transfer")

    new_owner = db.get(models.User, transfer.new_owner_id)
    if not new_owner or new_owner not in room.participants:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New owner must be a participant")

    room.created_by = new_owner.id
    db.commit()
    db.refresh(room)
    return room


@app.post("/rooms/{room_id}/playback", response_model=schemas.RoomOut)
def update_playback(room_id: int, payload: schemas.PlaybackUpdate, db: Session = Depends(get_db)):
    room = db.get(models.Room, room_id)
    if not room:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")

    # Only the creator controls playback
    if room.created_by != payload.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only room creator can control playback")

    room.playback_position = payload.position
    room.is_playing = payload.is_playing
    room.playback_updated_at = datetime.utcnow()
    db.commit()
    db.refresh(room)
    room_playback_state[room.id] = {
        "video_url": room.video_url,
        "position": room.playback_position,
        "is_playing": room.is_playing,
        "updated_at": room.playback_updated_at.isoformat(timespec="milliseconds") + "Z",
    }
    return room


@app.get("/rooms/{room_id}/messages", response_model=List[schemas.MessageOut])
def list_messages(room_id: int, db: Session = Depends(get_db)):
    room = db.get(models.Room, room_id)
    if not room:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")
    messages = (
        db.query(models.Message)
        .filter(models.Message.room_id == room_id)
        .order_by(models.Message.created_at.asc())
        .all()
    )
    return messages


@app.post("/rooms/{room_id}/messages", response_model=schemas.MessageOut, status_code=status.HTTP_201_CREATED)
def create_message(room_id: int, msg: schemas.MessageCreate, db: Session = Depends(get_db)):
    room = db.get(models.Room, room_id)
    if not room:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")
    user = db.get(models.User, msg.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user not in room.participants:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User not in room")

    new_msg = models.Message(room_id=room_id, user_id=user.id, text=msg.text)
    db.add(new_msg)
    db.commit()
    db.refresh(new_msg)
    return new_msg


@app.websocket("/ws/rooms/{room_id}")
async def room_ws(websocket: WebSocket, room_id: int):
    db = SessionLocal()
    try:
        room = db.get(models.Room, room_id)
        user_id_param = websocket.query_params.get("user_id")
        if not room or not user_id_param:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        try:
            user_id_int = int(user_id_param)
        except ValueError:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        user = db.get(models.User, user_id_int)
        if not user or user not in room.participants:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        await websocket.accept()
        room_connections.setdefault(room_id, []).append(websocket)
        _ensure_room_state(room)

        # Enviar estado atual, se existir
        state = room_playback_state.get(room_id)
        if state:
            await websocket.send_json({"type": "state", **state})

        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type")
            msg_user_id = data.get("user_id")

            # Garante que o user_id enviado coincide com o autenticado na conexao
            if msg_user_id is not None and int(msg_user_id) != user_id_int:
                await websocket.send_json({"type": "error", "detail": "user mismatch"})
                continue

            if msg_type == "playback":
                # Apenas o criador pode controlar
                if room.created_by != user_id_int:
                    await websocket.send_json({"type": "error", "detail": "not room owner"})
                    continue

                room.playback_position = float(data.get("position", 0))
                room.is_playing = bool(data.get("is_playing", False))
                incoming_url = data.get("video_url") or room.video_url
                room.video_url = incoming_url
                room.playback_updated_at = datetime.utcnow()
                db.commit()
                db.refresh(room)

                state = {
                    "video_url": room.video_url,
                    "position": room.playback_position,
                    "is_playing": room.is_playing,
                    "updated_at": room.playback_updated_at.isoformat(timespec="milliseconds") + "Z",
                }
                room_playback_state[room_id] = state
                await _broadcast(room_id, {"type": "state", **state})
            elif msg_type == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    finally:
        room_connections[room_id] = [ws for ws in room_connections.get(room_id, []) if ws is not websocket]
        db.close()

