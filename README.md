# Сбор статистики просмотров постов в социальных сетях
Этот проект представляет собой сервис для сбора статистики по просмотрам постов в различных социальных сетях. С помощью этого сервиса вы можете отправлять запросы на сбор просмотров с постов и получать список постов со статусами задачи.
## Установка и запуск
1. Установите все зависимости, указанные в файле requirements.txt, используя команду:
`pip install -r requirements.txt`
2. Укажите все необходимые переменные окружения в файле .env.
3. Запустите приложение с помощью команды:
`uvicorn main:app --host 0.0.0.0 --port 8000`
## API Эндпоинты
/token
Метод: POST
Описание: Этот эндпоинт предназначен для аутентификации пользователя и выдачи токена доступа.
Параметры:
username: имя пользователя
password: пароль пользователя
Возвращаемые данные: Токен доступа
