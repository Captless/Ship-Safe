import os

DEBUG = True

def run(cmd):
    os.system(f"ping {cmd}")

def query(user_id):
    sql = "SELECT * FROM users WHERE id = " + user_id
    return sql

SECRET_KEY = "shortkey"
