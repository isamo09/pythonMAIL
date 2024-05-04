from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
import sqlite3
from functools import wraps
import os
import json
import re

app = Flask(__name__)
app.secret_key = "admin_key"
app.key = "key"

DATABASE = "mail.db"


def load_propertis():
    global version, reg_limit, admin_page
    with open("properties.json", "r") as file:
        data = json.load(file)

    version = data.get("version")
    admin_key = data.get("admin_key")
    limit = data.get("reg_limit")
    reset_reg_counts = data.get("reset_reg_counts")
    admin_page = data.get("admin_page")
    key = data.get("key")
    if admin_key == False:
        pass
    else:
        app.secret_key = admin_key
    if key == False:
        pass
    else:
        app.key = key
    if reset_reg_counts == True:
        reset_registration_counts()
    if limit == None:
        reg_limit = 999
    else:
        reg_limit = int(limit)
    print(f"Version: {version}")


def create_database():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT NOT NULL,
                 email TEXT NOT NULL,
                 password TEXT NOT NULL,
                 is_banned INTEGER NOT NULL DEFAULT 0,
                 threat_level INTEGER NOT NULL DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS emails
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 sender_id INTEGER NOT NULL,
                 receiver_id INTEGER NOT NULL,
                 subject TEXT NOT NULL,
                 message TEXT NOT NULL)''')
    conn.commit()
    conn.close()


def check_censorship(text, user_id):
    text = text.lower()
    with open("none.txt", "r", encoding="utf-8") as file:
        censor_words = [word.strip().lower() for word in file.readlines()]
    for word in censor_words:
        if word in text:
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute("UPDATE users SET threat_level = threat_level + 1 WHERE id=?", (user_id,))
            conn.commit()
            conn.close()
            return True
    return False


def update_registration_count(ip_address):
    global reg_limit
    registration_counts_file = "registration_counts.txt"

    registration_counts = {}
    if os.path.exists(registration_counts_file):
        with open(registration_counts_file, "r") as file:
            for line in file:
                ip, count = line.strip().split(":")
                registration_counts[ip] = int(count)

    if ip_address in registration_counts:
        registration_counts[ip_address] += 1
    else:
        registration_counts[ip_address] = 1

    if registration_counts[ip_address] > reg_limit:
        return False

    with open(registration_counts_file, "w") as file:
        for ip, count in registration_counts.items():
            file.write(f"{ip}:{count}\n")

    return True


def normalize_email(email):
    return email.lower()


def reset_registration_counts():
    registration_counts_file = "registration_counts.txt"
    with open(registration_counts_file, "r") as file:
        lines = file.readlines()

    with open(registration_counts_file, "w") as file:
        for line in lines:
            ip, count = line.strip().split(":")
            file.write(f"{ip}:0\n")


def require_admin(view_func):
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        admin_key = request.args.get("admin_key")
        if admin_key != app.secret_key:
            return redirect("/")
        return view_func(*args, **kwargs)
    return decorated_view


def validate_email(email):
    pattern = r'^[A-Za-z0-9_-]+@mail+\.[A-Za-z]{2,6}$'
    return bool(re.match(pattern, email))


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.route("/")
def index():
    user_id = session.get("user_id")
    user_email = None
    if user_id:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT email FROM users WHERE id=?", (user_id,))
        user_email = c.fetchone()
        conn.close()
        if user_email:
            user_email = user_email[0]
    return render_template("index.html", user_email=user_email)


@app.route("/register", methods=["GET", "POST"])
def register():
    load_propertis()
    if request.method == "POST":
        username = request.form["username"]
        email = normalize_email(request.form["email"])
        password = request.form["password"]
        agree = request.form.get("agree")

        if not agree:
            flash("Вы должны согласиться с правилами использования.")
            return render_template("register.html")

        if not update_registration_count(request.remote_addr):
            return render_template("error.html", message="Вы превысили лимит регистраций с вашего IP-адреса. Попробуйте снова после перезагрузки сервера.")

        if not validate_email(email):
            return render_template("error.html", message="Пожалуйста, введите корректный адрес электронной почты.")

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()

        c.execute("SELECT * FROM users WHERE email=?", (email,))
        existing_user = c.fetchone()

        if existing_user:
            return render_template("error.html", message="Пользователь с таким email уже существует.")

        c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, password))
        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    load_propertis()
    if request.method == "POST":
        email = normalize_email(request.form["email"])
        password = request.form["password"]

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=? AND password=?", (email, password))
        user = c.fetchone()
        conn.close()

        if user:
            if user[4] == 1:
                return render_template("is_ban.html", message="Вы не можете войти.")
            else:
                session["user_id"] = user[0]
                return redirect("/inbox")
        else:
            return redirect("/login")

    return render_template("login.html")


@app.route("/inbox")
def inbox():
    user_id = session.get("user_id")

    if user_id:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT emails.id, users.email, emails.subject, emails.message FROM emails JOIN users ON emails.sender_id = users.id WHERE emails.receiver_id=?", (user_id,))
        emails = c.fetchall()
        conn.close()

        return render_template("inbox.html", emails=emails)
    else:
        return redirect("/login")


@app.route("/view_email/<int:email_id>")
def view_email(email_id):
    user_id = session.get("user_id")

    if user_id:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT users.email, emails.subject, emails.message FROM emails JOIN users ON emails.sender_id = users.id WHERE emails.id=? AND emails.receiver_id=?", (email_id, user_id))
        email = c.fetchone()
        conn.close()

        if email:
            return render_template("view_email.html", email=email)
        else:
            return redirect("/inbox")
    else:
        return redirect("/login")


@app.route("/delete_email/<int:email_id>")
def delete_email(email_id):
    load_propertis()
    user_id = session.get("user_id")

    if user_id:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("DELETE FROM emails WHERE id=? AND receiver_id=?", (email_id, user_id))
        conn.commit()
        conn.close()

    return redirect("/inbox")


@app.route("/update_emails")
def update_emails():
    user_id = session.get("user_id")
    if user_id:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT emails.id, users.email, emails.subject, emails.message FROM emails JOIN users ON emails.sender_id = users.id WHERE emails.receiver_id=? ORDER BY emails.id DESC", (user_id,))
        emails = c.fetchall()
        conn.close()

        emails_html = "".join([f'<div class="email" onclick="showEmailDetails({email[0]})"><h3>Отправитель: {email[1]}</h3><h4>Тема: {email[2]}</h4><p>{email[3]}</p><a href="/view_email/{email[0]}">Просмотреть</a><a href="/delete_email/{email[0]}">Удалить</a></div>' for email in emails])

        return emails_html
    else:
        return redirect("/login")


@app.route("/compose", methods=["GET", "POST"])
def compose():
    load_propertis()
    if request.method == "POST":
        user_id = session.get("user_id")

        if user_id:
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute("SELECT is_banned FROM users WHERE id=?", (user_id,))
            user = c.fetchone()
            conn.close()

            if user[0] == 1:
                return render_template("is_ban.html", message="Вы не можете отправлять письма.")

            receiver_email = normalize_email(request.form["receiver_email"])
            subject = request.form["subject"]
            message = request.form["message"]

            if check_censorship(subject, user_id) or check_censorship(message, user_id):
                return render_template("ban.html")

            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute("SELECT id FROM users WHERE email=?", (receiver_email,))
            receiver = c.fetchone()

            if receiver:
                receiver_id = receiver[0]
                c.execute("INSERT INTO emails (sender_id, receiver_id, subject, message) VALUES (?, ?, ?, ?)", (user_id, receiver_id, subject, message))
                conn.commit()

            conn.close()

            return redirect("/inbox")
        else:
            return redirect("/login")

    return render_template("compose.html")


@app.route("/sent_json")
def sent_json():
    load_propertis()
    user_id = session.get("user_id")
    if user_id:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT emails.id, users.email as receiver_email, emails.subject, emails.message FROM emails JOIN users ON emails.receiver_id = users.id WHERE emails.sender_id=? ORDER BY emails.id ASC", (user_id,))
        sent_emails = c.fetchall()
        conn.close()
        return jsonify(sent_emails)
    else:
        return redirect("/login")


@app.route("/sent")
def sent():
    return render_template("sent.html")


@app.route("/about")
def about():
    load_propertis()
    try:
        with open("none.txt", "r", encoding="utf-8") as file:
            forbidden_words = [word.strip() for word in file.readlines()]
    except FileNotFoundError:
        forbidden_words = []
        print("File 'none.txt' not found. Please ensure the file exists and is accessible.")
    except Exception as e:
        forbidden_words = []
        print(f"An error occurred while reading 'none.txt': {e}")

    return render_template("about.html", forbidden_words=forbidden_words, version=version)


@app.route("/logo")
def main():
    return render_template("dedsec.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/news")
def news():
    load_propertis()
    news_directory = "news"
    news_items = []
    for news_id in os.listdir(news_directory):
        news_path = os.path.join(news_directory, news_id)
        if os.path.isdir(news_path):
            info_path = os.path.join(news_path, "info.json")
            text_path = os.path.join(news_path, "text.txt")
            img_path = None
            for img_file in ["img.gif", "img.png", "img.jpeg"]:
                img_file_path = os.path.join(news_path, img_file)
                if os.path.exists(img_file_path):
                    img_path = img_file_path
                    break
            if os.path.exists(info_path) and os.path.exists(text_path):
                with open(info_path, "r", encoding="utf-8") as info_file:
                    info_data = json.load(info_file)
                with open(text_path, "r", encoding="utf-8") as text_file:
                    text_data = text_file.read()
                news_items.append({
                    "id": news_id,
                    "info": info_data,
                    "text": text_data,
                    "img": img_path if img_path else None
                })
    news_items.sort(key=lambda x: x["info"]["publication_date"], reverse=True)
    return jsonify(news_items)


@app.route("/get_user_email")
def get_user_email():
    user_id = session.get("user_id")
    user_email = None
    if user_id:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT email FROM users WHERE id=?", (user_id,))
        user_email = c.fetchone()
        conn.close()
        if user_email:
            user_email = user_email[0]
    return jsonify({"email": user_email})


@app.route("/settings", methods=["GET", "POST"])
def settings():
    load_propertis()
    user_id = session.get("user_id")
    if user_id:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE id=?", (user_id,))
        user = c.fetchone()
        if user[4] == 1:
            return render_template("is_ban.html", message="Вы не можете изменять настройки.")

        if request.method == "POST":
            if "password_confirmed" not in session or not session["password_confirmed"]:
                return render_template("confirm_password.html", user_id=user_id, action="settings")

            new_username = request.form["new_username"]
            new_email = normalize_email(request.form["new_email"])
            new_password = request.form["new_password"]
            change_password = request.form.get("change_password")

            c.execute("SELECT * FROM users WHERE email=? AND id!=?", (new_email, user_id))
            existing_user = c.fetchone()
            if existing_user:
                return render_template("error.html", message="Пользователь с таким email уже существует.")

            if not validate_email(new_email):
                return render_template("error.html", message="Пожалуйста, введите корректный адрес электронной почты.")

            if change_password and not new_password:
                return render_template("error.html", message="Пожалуйста, введите новый пароль.")

            c.execute("UPDATE users SET username=?, email=? WHERE id=?", (new_username, new_email, user_id))

            if change_password:
                c.execute("UPDATE users SET password=? WHERE id=?", (new_password, user_id))

            conn.commit()
            conn.close()
            session["password_confirmed"] = None
            session.pop("password_confirmed", None)

            return redirect("/settings")

        conn.close()

        return render_template("settings.html", user=user)
    else:
        return redirect("/login")


@app.route("/admin", methods=["GET", "POST"])
def admin():
    load_propertis()
    if not admin_page:
        return render_template("404.html"), 404
    access_key = request.args.get("key")
    if access_key != app.key:
        return redirect("/")
    return redirect(f"admin_key_entry?access_key={access_key}")


@app.route("/admin_key_entry", methods=["GET", "POST"])
def admin_key_entry():
    if not admin_page:
        return render_template("404.html"), 404
    access_key = request.args.get("access_key")
    if access_key != app.key:
        return redirect("/")
    if request.method == "POST":
        return admin_key_check()
    return render_template("admin_key_entry.html")


@app.route("/admin_key_check", methods=["POST"])
def admin_key_check():
    if not admin_page:
        return render_template("404.html"), 404
    admin_key = request.form.get("admin_key")
    if admin_key == app.secret_key:
        session["admin_key"] = admin_key
        return redirect(url_for("admin_panel"))
    else:
        return render_template("404.html"), 404


@app.route("/admin_panel")
def admin_panel():
    load_propertis()
    if admin_page == True:
        if "admin_key" in session and session["admin_key"] == app.secret_key:
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute("SELECT * FROM users")
            users = c.fetchall()
            conn.close()

            return render_template("admin.html", users=users)
        else:
            return redirect(url_for("admin_key_entry"))
    else:
        return render_template("404.html"), 404


@app.route("/confirm_action/<int:user_id>/<action>", methods=["GET", "POST"])
def confirm_action(user_id, action):
    load_propertis()
    if not admin_page:
        return render_template("404.html"), 404
    if "admin_key" in session and session["admin_key"] == app.secret_key:
        if request.method == "POST":
            admin_key = request.form["admin_key"]
            if admin_key == app.secret_key:
                session['admin_authorized'] = True
                conn = sqlite3.connect(DATABASE)
                c = conn.cursor()
                if action == "ban":
                    c.execute("UPDATE users SET is_banned=1 WHERE id=?", (user_id,))
                    conn.commit()
                    flash("Пользователь успешно забанен.")
                elif action == "unban":
                    c.execute("UPDATE users SET is_banned=0, threat_level=0 WHERE id=?", (user_id,))
                    conn.commit()
                    flash("Пользователь успешно разбанен.")
                elif action == "delete":
                    c.execute("DELETE FROM users WHERE id=?", (user_id,))
                    conn.commit()
                    flash("Пользователь успешно удален.")
                else:
                    flash("Неизвестное действие.")
                conn.close()
                return redirect(url_for("admin_panel"))
            else:
                flash("Неверный ключ. Попробуйте снова.")
                return redirect(url_for("admin_panel"))
        return render_template("confirm_action.html", user_id=user_id, action=action)
    else:
        return render_template("404.html"), 404


@app.route("/ban_user/<int:user_id>")
def ban_user(user_id):
    load_propertis()
    if not admin_page:
        return render_template("404.html"), 404
    if "admin_authorized" in session and session["admin_authorized"] != True:
        return redirect("/")
    if "admin_key" in session and session["admin_key"] == app.secret_key:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("UPDATE users SET is_banned=1 WHERE id=?", (user_id,))
        conn.commit()
        conn.close()
        session['admin_authorized'] = False
        return redirect("/admin")
    return redirect("/")


@app.route("/unban_user/<int:user_id>")
def unban_user(user_id):
    load_propertis()
    if not admin_page:
        return render_template("404.html"), 404
    if "admin_authorized" in session and session["admin_authorized"] != True:
        return redirect("/")
    if "admin_key" in session and session["admin_key"] == app.secret_key:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("UPDATE users SET is_banned=0, threat_level=0 WHERE id=?", (user_id,))
        conn.commit()
        conn.close()
        session['admin_authorized'] = False
        return redirect("/admin")
    return redirect("/")


@app.route("/delete_account")
def delete_account():
    user_id = session.get("user_id")
    if user_id:
        return render_template("confirm_password.html")
    else:
        return redirect("/login")


@app.route("/confirm_password", methods=["POST", "GET"])
def confirm_password():
    user_id = session.get("user_id")
    if user_id:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT is_banned FROM users WHERE id=?", (user_id,))
        user = c.fetchone()
        conn.close()

        if user[0] == 1:
            return render_template("is_ban.html", message="Вы не можете удалить этот аккаунт.")
    if user_id:
        entered_password = request.form.get("password")
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE id=?", (user_id,))
        user_password = c.fetchone()
        conn.close()

        if user_password and entered_password == user_password[0]:
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute("DELETE FROM users WHERE id=?", (user_id,))
            conn.commit()
            conn.close()
            session.pop("user_id", None)
            return redirect("/")
        else:
            return render_template("error.html", message="Неверный пароль.")
    else:
        return redirect("/login")


@app.route("/confirm_pass", methods=["POST", "GET"])
def confirm_pass():
    load_propertis()
    user_id = session.get("user_id")
    action = request.args.get("action")

    if user_id:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT is_banned FROM users WHERE id=?", (user_id,))
        user = c.fetchone()
        conn.close()

        if user[0] == 1:
            return render_template("is_ban.html", message="Вы не можете подтвердить эти изменения.")
    if action == "settings":
        if user_id:
            entered_password = request.form.get("password")
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute("SELECT password FROM users WHERE id=?", (user_id,))
            user_password = c.fetchone()
            conn.close()
            if user_password and entered_password == user_password[0]:
                session["password_confirmed"] = True
                return redirect("/settings")
            else:
                return render_template("error.html", message="Неверный пароль.")
    else:
        return render_template("error.html", message="Действие не найдено")


@app.route("/logout")
def logout():
    load_propertis()
    session.pop("user_id", None)
    return redirect("/")


if __name__ == "__main__":
    load_propertis()
    create_database()
    app.run(host="0.0.0.0", port=5000, debug=False)
