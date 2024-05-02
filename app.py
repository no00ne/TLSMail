from flask import Flask, request, render_template, jsonify, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from smtplib import SMTP
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import psycopg2
import Config

app = Flask(__name__)
app.secret_key = 'your secret key'

login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin):
    def __init__(self, id):
        self.id = id


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/mailbox')
@login_required
def mailbox():
    return render_template('mailBox.html')


@app.route('/send_mail', methods=['POST'])
@login_required
def send_mail():
    data = request.get_json()
    to = data['to']
    subject = data['subject']
    content = data['content']

    msg = MIMEMultipart()
    msg['From'] = current_user.username
    msg['To'] = to
    msg['Subject'] = subject
    msg.attach(MIMEText(content, 'plain'))

    client = SMTP(Config.get_smtp_server(), Config.get_smtp_port())
    client.login(current_user.username, current_user.password)
    client.send_message(msg)

    return 'Mail sent successfully'


@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    conn = psycopg2.connect(host=Config.get_pg_host(), port=Config.get_pg_port(), dbname=Config.get_pg_database(),
                            user=Config.get_pg_user(), password=Config.get_pg_password())
    cur = conn.cursor()
    cur.execute("SELECT * FROM public.User WHERE username = %s", (username,))
    if cur.fetchone() is not None:
        return 'Username already exists'
    cur.execute("INSERT INTO public.User (username, password) VALUES (%s, %s)", (username, password))
    conn.commit()
    return 'Registered successfully'


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    conn = psycopg2.connect(host=Config.get_pg_host(), port=Config.get_pg_port(), dbname=Config.get_pg_database(),
                            user=Config.get_pg_user(), password=Config.get_pg_password())
    cur = conn.cursor()
    cur.execute("SELECT * FROM public.User WHERE username = %s AND password = %s", (username, password))
    if cur.fetchone() is not None:
        user = User(username)
        login_user(user)
        return redirect(url_for('mailbox'))
    return 'Invalid username or password'


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return 'Logged out successfully'


@login_manager.user_loader
def load_user(user_id):
    conn = psycopg2.connect(host=Config.get_pg_host(), port=Config.get_pg_port(), dbname=Config.get_pg_database(),
                            user=Config.get_pg_user(), password=Config.get_pg_password())
    cur = conn.cursor()
    cur.execute("SELECT * FROM public.User WHERE username = %s", (user_id,))
    if cur.fetchone() is not None:
        return User(user_id)
    return None


@app.route('/user')
@login_required
def user():
    return jsonify({'username': current_user.username})


if __name__ == '__main__':
    app.run()
