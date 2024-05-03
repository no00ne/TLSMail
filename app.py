import ssl

from flask import Flask, request, render_template, jsonify, request, redirect, url_for
from flask_bcrypt import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from smtplib import SMTP_SSL
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import psycopg2
import Config

app = Flask(__name__)
app.secret_key = 'your secret key'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = '/'


class User(UserMixin):
    def __init__(self, id, password):
        self.id = id
        self.password = password

    def get_id(self):
        return self.id

    def get_password(self):
        return self.password


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
    msg['From'] = current_user.id
    msg['To'] = to
    msg['Subject'] = subject
    msg.attach(MIMEText(content, 'plain'))

    client = SMTP_SSL(Config.get_smtp_server(), Config.get_smtp_port())
    client.login(current_user.id, current_user.password)
    client.send_message(msg)

    return 'Mail sent successfully'


@app.route('/receive_mail', methods=['GET'])
@login_required
def receive_mail():
    # return all emails in the database belong to login user
    conn = psycopg2.connect(host=Config.get_pg_host(), port=Config.get_pg_port(), dbname=Config.get_pg_database(),
                            user=Config.get_pg_user(), password=Config.get_pg_password())
    cur = conn.cursor()
    cur.execute("SELECT sender,date,subject,ep.content_type,ep.body FROM public.mail join public.email_parts ep on mail.id = ep.email_id WHERE recipient = %s",
                (current_user.id,))
    mails = cur.fetchall()
    return jsonify(mails)


@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    conn = psycopg2.connect(host=Config.get_pg_host(), port=Config.get_pg_port(), dbname=Config.get_pg_database(),
                            user=Config.get_pg_user(), password=Config.get_pg_password())
    cur = conn.cursor()
    cur.execute("SELECT * FROM public.User WHERE username = %s", (username,))
    if cur.fetchone() is not None:
        return 'User already exists'
    hashed_password = generate_password_hash(password, 10).decode('utf-8')
    cur.execute("INSERT INTO public.User (username, password) VALUES (%s, %s)", (username, hashed_password))
    conn.commit()
    return 'Registered successfully'


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    conn = psycopg2.connect(host=Config.get_pg_host(), port=Config.get_pg_port(), dbname=Config.get_pg_database(),
                            user=Config.get_pg_user(), password=Config.get_pg_password())
    cur = conn.cursor()
    cur.execute("SELECT * FROM public.User WHERE username = %s", (username,))
    user_record = cur.fetchone()
    if user_record is not None and check_password_hash(user_record[2], password):
        user = User(username, user_record[2])
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
    user_record = cur.fetchone()
    if user_record is not None:
        return User(user_id, user_record[2])
    raise Exception('User not found')


if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('certificates/certificate.crt', 'certificates/private.key')
    app.run(host=Config.get_flask_host(),ssl_context=context,debug=True)
