# main.py
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv
import os
import requests

# Загрузка переменных среды из файла .env
load_dotenv()

# Секретный ключ для JWT
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

# Примеры пользователей
USERS = {
    "testuser": {
        "username": "testuser",
        "password_hash": "$2b$12$ym3o1WZyslEGVfh1EzU61O9j.UA0STKJp8HE7zT.2V5gNEjNbzJJ6",  # пароль "testpassword"
    }
}

# Функция для проверки пароля
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Функция для получения пользователя
def get_user(username: str):
    if username in USERS:
        user_dict = USERS[username]
        return UserInDB(**user_dict)

# Функция для аутентификации пользователя
def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.password_hash):
        return False
    return user

# Функция для создания токена доступа
def create_access_token(data: dict):
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Функция для проверки токена
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Невозможно проверить учетные данные",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user

# Хэширование пароля
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

class User(BaseModel):
    username: str
    password: str

class UserInDB(User):
    password_hash: str

class Token(BaseModel):
    access_token: str
    token_type: str

# Зависимость для аутентификации
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Сущность для хранения информации о постах
class Post(BaseModel):
    url: str
    status: str
    views: int = None # Для хранения количества просмотров

# Симуляция хранилища для задач по сбору статистики
tasks_storage = []

# Эндпоинт для отправки запроса на сбор статистики с поста
@app.post("/collect_views/")
async def collect_views(background_tasks: BackgroundTasks, urls: List[str] = Form(...), current_user: User = Depends(get_current_user)):
    # Логика сбора просмотров по предоставленным URL
    for url in urls:
        tasks_storage.append({"url": url, "status": "назначена"})
    background_tasks.add_task(collect_views_task, urls)
    return {"message": "Задача на сбор просмотров запланирована"}

# Задача для сбора просмотров по URL
def collect_views_task(urls: List[str]):
    # Логика сбора просмотров по предоставленным URL
    for url in urls:
        # Пример парсинга просмотров с использованием requests
        try:
            response = requests.get(url)
            views = parse_views(response.text)
            update_post_status(url, "true", views)
        except Exception as e:
            update_post_status(url, "false")

# Функция для парсинга просмотров
def parse_views(html_content: str) -> int:
    # Пример парсинга просмотров из HTML контента
    # Здесь может быть ваша логика парсинга
    return 1000  # Возвращаем примерное количество просмотров

# Функция для обновления статуса поста и количества просмотров
def update_post_status(url: str, status: str, views: int = None):
    for task in tasks_storage:
        if task["url"] == url:
            task["status"] = status
            if status == "успешно":
                task["views"] = views

# Эндпоинт для получения списка постов со статусом задачи
@app.get("/posts/")
async def get_posts(current_user: User = Depends(get_current_user)):
    posts_with_status = []
    for task in tasks_storage:
        post = Post(url=task["url"], status=task["status"])
        if task["status"] == "успешно":
            post.views = task["views"]
        posts_with_status.append(post)
    return posts_with_status

# Эндпоинт для аутентификации и выдачи токена доступа
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Неверное имя пользователя или пароль",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
