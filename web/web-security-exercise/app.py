from flask import Flask, render_template, request
import sqlite3



# 连接数据库
def connect_db():
    db = sqlite3.connect("test.db")
    db.cursor().execute(
        "CREATE TABLE IF NOT EXISTS comments "
        "(id INTEGER PRIMARY KEY, "
        "comment TEXT)"
    )
    db.cursor().execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username VARCHAR(64),"
        "salt CHAR(64), pw CHAR(64))"
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


# 添加评论
def add_comment(comment):
    db = connect_db()
    db.cursor().execute("INSERT INTO comments (comment) " "VALUES (?)", (comment,))
    db.commit()


# 得到评论
def get_comments(search_query=None):
    db = connect_db()
    results = []
    get_all_query = "SELECT comment FROM comments"
    for (comment,) in db.cursor().execute(get_all_query).fetchall():
        if search_query is None or search_query in comment:
            results.append(comment)
    return results

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
    db.cursor().execute("INSERT INTO users (username, salt, pw) " "VALUES (?,?,?)", (username, salt, hash))
    db.commit()
    print(username, pw, salt, hash)
    
    return "注册成功"


@check_username
def login(username, pw):
    db = connect_db()
    for (u,s,p) in db.cursor().execute("SELECT username, salt, pw FROM users WHERE username = ?" , (username,)).fetchall():
        print(u,s,p)
        hash = get_hash(s, pw)
        if(p == hash):
            return "登录成功"
        else:
            return "用户名或密码错误"
        
    return "用户名或密码错误"


def login_insecure(username, pw):
    db = connect_db()
    for (s) in db.cursor().execute("SELECT salt FROM users WHERE username = '{}'".format(username)).fetchall():
        print(s)
        hash = get_hash(s[0], pw)
        
        try:
            sql = "SELECT username FROM users WHERE username = '{}' AND pw = '{}'".format(username, hash)
            print(sql)
            for _ in db.cursor().execute(sql).fetchall():   
                return "登录成功"
        except Exception as e:
            print(e)
            return "用户名或密码错误"

        
    return "用户名或密码错误"



# 启动flask
app = Flask(__name__)

INSECURE = True

@app.route("/", methods=["GET", "POST"])
def index():
    message = None
    if request.method == "POST":
        if "comment" in request.form:
            add_comment(request.form["comment"])
        elif "user_name_register" in request.form:
            message = register(
                request.form["user_name_register"], request.form["password"]
            )
        elif "user_name_login" in request.form:
            func = login_insecure if INSECURE else login
            message = func(request.form["user_name_login"], request.form["password"])

    search_query = request.args.get("q")

    comments = get_comments(search_query)
    

    return render_template(
        "index_insecure.html" if INSECURE else "index.html"
        , comments=comments, search_query=search_query, message=message
    )
    
@app.route("/attack")
def attack():
    return render_template("attack.html")
    
