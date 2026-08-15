import os

DEBUG = os.getenv("DEBUG", "false").lower() == "true"

def query(user_id):
    sql = "SELECT * FROM users WHERE id = %s"
    return (sql, user_id)

SECRET_KEY = os.getenv("SECRET_KEY", "")
