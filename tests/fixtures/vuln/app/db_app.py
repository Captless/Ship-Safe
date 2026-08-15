from flask import Flask, request

app = Flask(__name__)

CONN = "postgresql://admin:password123@db.example.com:5432/app"

@app.route("/api/user")
def user():
    uid = request.args.get("id")
    row = f"SELECT * FROM users WHERE id = {uid}"
    return row
