from flask import Flask, render_template, request, redirect,make_response
import sqlite3

from flask_wtf.csrf import CSRFProtect

from flask_cors import cross_origin

import os 
# 启动flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(64)

INSECURE = True

if not INSECURE:
    csrf = CSRFProtect(app)



# 连接数据库
def connect_db():
    db = sqlite3.connect("test.db")

    db.cursor().execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username VARCHAR(64),"
        "salt CHAR(64), pw CHAR(64) ,balance INT)"
    )
    db.commit()
    return db


import hashlib
import string
import random
import time


def get_hash(salt, pw):
    sha256 = hashlib.sha256()
    sha256.update(salt.encode("utf-8"))
    sha256.update(pw.encode("utf-8"))
    return sha256.hexdigest()


def get_salt_and_hash(pw):
    chars = string.ascii_letters + string.digits
    salt = "".join(random.choice(chars) for _ in range(64))
    return salt, get_hash(salt, pw)



from functools import wraps

def check_username(func):
    def is_username_legal(user_name):
        if(len(user_name) < 5):
            return False
        chars = string.ascii_letters + string.digits
        for i in user_name:
            if i not in chars:
                return False
        return True

    def wrapper(*args, **kwargs):
        if len(args) > 0 and isinstance(args[0], str) and is_username_legal(args[0]):
            return func(*args, **kwargs)
        else:
            return "illegal username。 用户名只能是[5,64]字符的数字或英文字母"
    return wrapper

@check_username
def register(username, pw):
    db = connect_db()

    for (u,) in db.cursor().execute("SELECT username FROM users WHERE username = ?", (username,)).fetchall():
        print(u)
        return "用户已存在"
    
    if(len(pw) < 10):
        return "密码不能短于10个字符"
    
    salt, hash = get_salt_and_hash(pw)
    
    db = connect_db()
    db.cursor().execute("INSERT INTO users (username, salt, pw, balance) " "VALUES (?,?,?,?)", (username, salt, hash, 10000))
    db.commit()
    print(username, pw, salt, hash)
    
    return "注册成功, 初始余额10 000"


@check_username
def handle_login(username, pw):
    db = connect_db()
    for (u,s,p) in db.cursor().execute("SELECT username, salt, pw FROM users WHERE username = ?" , (username,)).fetchall():
        print(u,s,p)
        hash = get_hash(s, pw)
        if(p == hash):
            return "登录成功"
        else:
            return "用户名或密码错误"
        
    return "用户名或密码错误"


def get_balance(username):
    db = connect_db()
    for (b) in db.cursor().execute("SELECT balance FROM users WHERE username = ?" , (username,)).fetchall():
        return b[0]
    return -1

SECRET = "asdnfokjqhweo9ifuhqw9iofjhaoid248r5uy983h"

def get_username(request):
    try:
        cookie = request.cookies.get('username')
        print(cookie)
        [name, res] = cookie.split("_")
        sha256 = hashlib.sha256()
        sha256.update(name.encode("utf-8"))
        sha256.update(SECRET.encode("utf-8"))
        if(sha256.hexdigest() != res):
            return None
        return name
    except:
        return None
    

def make_cookie(username):
    sha256 = hashlib.sha256()
    sha256.update(username.encode("utf-8"))
    sha256.update(SECRET.encode("utf-8"))
    return username + "_" + sha256.hexdigest()



@app.route("/consume", methods=["POST"])
# @cross_origin()
def consume():
    username = get_username(request)
    if not username:
        print("cookie failed")
        return redirect("/")
    
    db = connect_db()
    try:
        amount = int(request.form['amount'])
        assert(amount >= 0)
    except:
        return "illegal amount"
    
    
    for (id, b) in db.cursor().execute("SELECT id, balance FROM users WHERE username = ?" , (username,)).fetchall():
        if(b < amount):
            return "insufficient balance"
        else:
            db.cursor().execute("UPDATE users SET balance = ? WHERE id = ?",(b - amount, id))
            db.commit()
            print("new balance", b - amount)
            return redirect("/")
        
    return redirect("/")


@app.route("/", methods=["GET", "POST"])
def index():
    message = None

    username = get_username(request)
    login = False
    
    if request.method == "POST":
        if "user_name_register" in request.form:
            message = register(
                request.form["user_name_register"], request.form["password"]
            )
        elif "user_name_login" in request.form:
            message = handle_login(request.form["user_name_login"], request.form["password"])
            if message == "登录成功":
                login = True
                username = request.form["user_name_login"]

    if(username):
        login = True
        remain = get_balance(username)
    else:
        login = False
        remain = -1
        

    resp =  render_template(
        "index.html" if INSECURE else "index_csrf.html"
        , remain = remain,  message=message, login = login, username = username
    )
    resp = make_response(resp)
    if(login):
        resp.set_cookie('username', make_cookie(username))
        
    return resp
    
    
#https://www.maxlist.xyz/2020/05/07/flask-csrf/


#https://www.maxlist.xyz/2019/05/11/flask-cookie/#google_vignette
