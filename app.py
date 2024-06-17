import datetime
import json
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from smtplib import SMTP
from typing import List, Tuple

import psycopg2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_bcrypt import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

import Config

app = Flask(__name__)
app.secret_key = 'your secret key'
CORS(app)

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
    subject = data['subject'].encode('utf-8')
    content = data['content'].encode('utf-8')

    msg = MIMEMultipart()
    msg['From'] = current_user.id
    msg['To'] = to
    msg['Subject'] = subject
    msg.attach(MIMEText(content, 'plain'))

    client = SMTP(Config.get_smtp_server(), Config.get_smtp_port())
    client.starttls()
    client.login(current_user.id, current_user.password)
    client.send_message(msg)

    return 'Mail sent successfully'


@app.route('/receive_mail', methods=['GET'])
@login_required
def receive_mail():
    # return all emails in the database belong to login user
    conn = getConnect()
    cur = conn.cursor()
    cur.execute(
        "SELECT sender,date,subject,ep.content_type,ep.body FROM public.mail join public.email_parts ep on mail.id = ep.email_id WHERE recipient = %s",
        (current_user.id,))
    mails = cur.fetchall()
    return jsonify(mails)


@app.route('/send_mail_with_sender', methods=['POST'])
def send_mail_with_sender():
    data = request.get_json()
    from_email = data['from']
    to = data['to']
    subject = data['subject']
    content = data['content']
    from_password = data['password']
    cc_address = data['cc']
    bcc_address = data['bcc']
    print(cc_address)
    # 将字节对象反序列化为字典
    encryption_data = data['encryption_data']

    conn = getConnect()
    cur = conn.cursor()

    cur.execute("SELECT * FROM public.User WHERE username = %s", (from_email,))
    user_record = cur.fetchone()
    if user_record is not None and user_record[2] == from_password:
        # msg = MIMEMultipart()
        # msg['From'] = from_email
        # msg['To'] = to
        # msg['Subject'] = subject
        # msg.attach(MIMEText(content, 'plain'))

        # Only add Cc and Bcc headers if they are not empty
        # if cc_address:
        # msg['Cc'] = cc_address
        # if bcc_address:
        #   msg['Bcc'] = bcc_address

        # client = SMTP(Config.get_smtp_server(), Config.get_smtp_port())
        # client.starttls()
        # client.login(from_email, from_password)
        # client.send_message(msg)
        # client.quit()

        # 存储邮件和加密数据
        if encryption_data:
            cur.execute("""
                INSERT INTO public.mail (sender, receiver, cc, bcc, date, encryption_data)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                from_email,
                to,
                cc_address if cc_address else None,  # 如果cc为空，插入NULL
                bcc_address if bcc_address else None,  # 如果bcc为空，插入NULL
                datetime.datetime.now(),
                json.dumps(encryption_data)
            ))
            conn.commit()

        return jsonify({'message': 'Mail sent successfully'})

    return jsonify({'message': 'Invalid username or password'}), 400


@app.route('/receive_mail_with_receiver', methods=['POST'])
def receive_mail_with_receiver():
    data = request.get_json()
    print("Received data:", data)  # 打印收到的数据以进行调试
    username = data.get('username')
    password = data.get('password')

    conn = getConnect()
    cur = conn.cursor()

    # 验证用户
    cur.execute("SELECT * FROM public.User WHERE username = %s", (username,))
    user_record = cur.fetchone()
    if user_record is None or not check_password_hash(user_record[2], password):
        return 'Invalid username or password', 400

    # 获取加密邮件及发送者的公钥
    cur.execute("""
        SELECT m.sender, m.receiver, m.cc, m.bcc, m.date, m.encryption_data, u.public_key_email_bytes
        FROM public.mail m
        JOIN public."user" u ON m.sender = u.username
        WHERE m.receiver = %s OR %s = ANY(m.cc) OR %s = ANY(m.bcc) OR m.sender = %s
        ORDER BY m.date DESC
    """, (username, username, username, username))
    mails = cur.fetchall()

    encrypted_mails = []
    for mail in mails:
        sender = mail[0]
        receiver = mail[1]
        cc = mail[2] if mail[2] else []
        bcc = mail[3] if mail[3] else []
        if sender != username:
            bcc = []  # 如果发送者不是当前用户，将 bcc 设置为空数组

        # 找到 username 在邮件中的位置
        participants = [sender] + [receiver] + cc + bcc
        user_index = participants.index(username)
        print(user_index)

        # 获取 encryption_data 并解码
        encryption_data = mail[5]
        recipient_ciphertext = encryption_data['recipient_ciphertexts'][user_index]
        xcha_nonce = encryption_data['xcha_nonces'][user_index]

        # 获取所有参与者的 user_ids
        cur.execute("""
            SELECT username, id
            FROM public."user"
            WHERE username = ANY(%s)
        """, (participants,))
        user_id_map = {row[0]: row[1] for row in cur.fetchall()}

        # 构建 user_ids 字符串
        user_ids_list = []
        for participant in participants:
            user_ids_list.append(str(user_id_map[participant]))
        user_ids_str = ",".join(user_ids_list)

        encrypted_mail = {
            'sender': sender,
            'receiver': receiver,
            'cc': cc,
            'bcc': bcc,
            'date': mail[4].isoformat(),
            'encryption_data': {
                'ciphertexts': encryption_data['ciphertexts'],
                'bcc_commitment': encryption_data['bcc_commitment'],
                'commitment_key': encryption_data['commitment_key'],
                'recipient_digests_signature': encryption_data['recipient_digests_signature'],
                'public_key': encryption_data['public_key'],
                'recipient_ciphertext': recipient_ciphertext,  # 只返回对应的 recipient_ciphertext
                'manifest_encrypted': encryption_data['manifest_encrypted'],
                'manifest_encrypted_hash': encryption_data['manifest_encrypted_hash'],
                'xcha_nonce': xcha_nonce,  # 只返回对应的 xcha_nonce
                'user_ids': user_ids_str  # 添加 user_ids 字符串
            },
            'sender_public_key': mail[6].hex()  # 将公钥转换为十六进制字符串
        }
        encrypted_mails.append(encrypted_mail)

    conn.close()

    return jsonify(encrypted_mails)


@app.route('/get_user_ids_and_public_keys', methods=['POST'])
def get_user_ids_and_public_keys() -> Tuple[List[int], List[ed25519.Ed25519PublicKey]]:
    data = request.get_json()
    from_address = data['from']
    to_address = data['to']
    cc_address = data.get('cc')
    bcc_address = data.get('bcc')
    # Collect all relevant addresses into a single list
    addresses = [from_address] + [to_address]
    if cc_address:
        addresses += cc_address
    if bcc_address:
        addresses += bcc_address
    print(addresses)


    conn = getConnect()
    with conn.cursor() as cur:
        # Construct the SQL query with placeholders for the addresses
        cur.execute("""
            SELECT username, id, public_key_email_bytes
            FROM public."user"
            WHERE username = ANY(%s)
        """, (addresses,))

        # Create a mapping from username to (id, public_key_email_bytes)
        user_map = {row[0]: (row[1], row[2]) for row in cur.fetchall()}
    print(user_map)
    # Build the user_ids and public_keys lists in the order of addresses
    user_ids = []
    public_keys = []
    for address in addresses:
        user_id, public_key_email_bytes = user_map[address]
        user_ids.append(user_id)
        public_key = x25519.X25519PublicKey.from_public_bytes(bytes(public_key_email_bytes))
        public_keys.append(public_key)
    print(user_ids)
    print(public_keys)

    # Convert public keys to hex representation for JSON serialization
    public_keys_hex = [
        key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
        for key in public_keys
    ]

    return jsonify({'user_ids': user_ids, 'public_keys': public_keys_hex})


@app.route('/upload_pkey', methods=['POST'])
def upload_pkey():
    data = request.get_json()
    username = data['username']
    pkey = data['pkey']
    conn = getConnect()
    with conn.cursor() as cur:
        cur.execute("INSERT INTO public.User (public_key_email_bytes,username) VALUES (%s,%s)", (pkey, username))

    conn.commit()
    return 'Upload Successfully'


@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    public_key_email_bytes = request.files['public_key_email_bytes'].read()  # Read the file in binary mode

    conn = getConnect()
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM public.user WHERE username = %s", (username,))
        if cur.fetchone()[0] > 0:
            conn.close()
            return 'Username already exists', 400
        hashed_password = generate_password_hash(password, 10).decode('utf-8')
        cur.execute("INSERT INTO public.user (username, password, public_key_email_bytes) VALUES (%s, %s, %s)",
                    (username, hashed_password, psycopg2.Binary(public_key_email_bytes)))
        conn.commit()
    conn.close()
    return 'Registered successfully'


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    conn = getConnect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM public.User WHERE username = %s", (username,))
    user_record = cur.fetchone()
    print(user_record[2])
    print(password)
    if user_record is not None and check_password_hash(user_record[2], password):
        user = User(username, user_record[2])
        login_user(user)
        print(current_user)
        print(current_user.id)
        return redirect(url_for('mailbox'))
    return 'Invalid username or password', 400


def getConnect():
    conn = psycopg2.connect(host=Config.get_pg_host(), port=Config.get_pg_port(), dbname=Config.get_pg_database(),
                            user=Config.get_pg_user(), password=Config.get_pg_password())
    return conn


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return 'Logged out successfully'


@login_manager.user_loader
def load_user(user_id):
    conn = getConnect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM public.User WHERE username = %s", (user_id,))
    user_record = cur.fetchone()
    if user_record is not None:
        return User(user_id, user_record[2])
    raise Exception('User not found')


if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('certificates/certificate.crt', 'certificates/private.key')
    app.run(host=Config.get_flask_host(), ssl_context=context, debug=True)
