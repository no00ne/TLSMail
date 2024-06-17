import base64
import os

import psycopg2
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from flask import Flask, render_template
from flask import request, jsonify
from flask_bcrypt import check_password_hash

import Config
import PUKs
import gpg
from decrypt import decrypt_email
from encrypt import main_encrypt

app = Flask(__name__)

current_user = None
current_password = None
current_skey = None
current_passphrase = None
url = 'https://26.26.26.1:5000/'
gnupg = gpg.GPG()
pg_host = Config.get_pg_host()
pg_port = Config.get_pg_port()
pg_database = Config.get_pg_database()
pg_user = Config.get_pg_user()
pg_password = Config.get_pg_password()
pg_localhost = Config.get_local_pg_host()
pg_localPassword = Config.get_localPassword()


def get_db_connection():
    return psycopg2.connect(host=pg_host, port=pg_port, database=pg_database, user=pg_user, password=pg_password)


@app.route('/')
def index():
    return render_template('index.html')


def read_from_file(directory, filename):
    path = os.path.join(directory, filename)
    with open(path, 'rb') as file:
        return file.read()


@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    if not username or not password:
        return 'Both username and password are required!', 400
    print("test")  # Debugging statement

    PUKs.generate_and_store_keys(username)
    public_key_email_bytes = read_from_file(username, 'public_email_x25519.bin')

    try:
        # Convert public_key_email_bytes to a format that can be sent in the request
        files = {
            'username': (None, username),
            'password': (None, password),
            'public_key_email_bytes': ('public_email_x25519.bin', public_key_email_bytes)
        }

        response = requests.post(url + "/register", files=files, verify=False)
        if response.status_code == 200:
            print("Registration successful!")
            print(response.text)
            return 'User registered successfully'
        else:
            print("Registration failed!")
            print(response.text)
            return 'Registration failed', response.status_code

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return 'Failed to communicate with the lower application', 500


@app.route('/store_username', methods=['POST'])
def store_username():
    username = request.form.get('username')
    global current_user
    current_user = username

    global current_password
    global current_passphrase
    current_passphrase = request.form.get('password')
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT password FROM public.user WHERE username = %s", (username,))
        result = cur.fetchone()
        if result and check_password_hash(result[0], current_passphrase):
            current_password = result[0]
            print('Username stored successfully')
            return 'Username stored successfully'
        else:
            print('Invalid username or password')
            return 'Invalid username or password', 400


@app.route('/access_username')
def access_username():
    global current_user
    return jsonify({'username': current_user, 'password': current_password})


@app.route('/mailbox')
def mailbox():
    return render_template('MailBox.html')


@app.route('/generate_key')
def generate_key():
    private_key = gnupg.generate_key(username=current_user, passphrase=current_password)
    global current_skey
    current_skey = private_key
    return jsonify({'private_key': private_key})


@app.route('/encrypt_message', methods=['POST'])
def encrypt_message():
    data = request.get_json()
    message = data['content']
    recipient = data['recipient']
    try:
        encrypted_message = gnupg.encrypt_message(message, recipient)
    except ValueError:
        return 'Error, maybe wrong recipient'
    return jsonify({'encrypted_message': encrypted_message.decode('utf-8')})


@app.route('/decrypt_message', methods=['POST'])
def decrypt_message():
    data = request.get_json()
    encrypted_message = data['content']
    try:
        decrypted_message = gnupg.decrypt_message(encrypted_message, current_passphrase).decode('utf-8')
    except ValueError:
        return 'Error, maybe wrong password'
    return jsonify({'decrypted_message': decrypted_message})


def get_user_ids_and_public_keys(from_address, to_address, cc_address=None, bcc_address=None):
    # 替换为实际服务器地址
    headers = {'Content-Type': 'application/json'}
    data = {
        'from': from_address,
        'to': to_address,
        'cc': cc_address,
        'bcc': bcc_address
    }

    try:
        response = requests.post(url + "get_user_ids_and_public_keys", json=data, headers=headers, verify=False)
        response.raise_for_status()

        data = response.json()
        try:
            user_ids = data['user_ids']
            public_keys_bytes = data['public_keys']
            public_keys = [x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(key)) for key in public_keys_bytes]
            return user_ids, public_keys
        except KeyError as e:
            print(f"Missing key in response data: {e}")
            raise
        except ValueError as e:
            print(f"Error processing public keys: {e}")
            raise
    except requests.RequestException as e:
        print(f"HTTP request failed: {e}")
        raise


@app.route('/send_mail_with_sender', methods=['POST'])
def send_mail_with_sender(conn=None):
    print("test")
    data = request.get_json()
    from_address = data['from']
    to_address = data['to']
    cc_address = data.get('cc', [])
    bcc_address = data.get('bcc', [])
    subject = data['subject']
    content = data['content']
    password = data['password']
    pieces = [subject, content]
    pieces = [s.encode('utf-8') for s in pieces]
    try:
        user_ids, public_keys = get_user_ids_and_public_keys(from_address, to_address, cc_address, bcc_address)
        print("User IDs:", user_ids)
        print("Public Keys:",
              [key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex() for
               key in public_keys])
    except Exception as e:
        print(f"An error occurred: {e}")

    # sender_device_private_key = read_from_file(from_address, 'private_email_x25519.bin')
    # sender_device_private_key = x25519.X25519PrivateKey.from_private_bytes(sender_device_private_key)
    user_ids_str_list = [str(user_id) for user_id in user_ids]
    # 将列表转换为逗号分隔的字符串
    user_ids = ",".join(user_ids_str_list)
    ciphertexts, bcc_commitment, commitment_key, recipient_digests_signature, public_key, recipient_ciphertexts, manifest_encrypted, manifest_encrypted_hash, xcha_nonces = main_encrypt(
        pieces, bcc_address, public_keys, user_ids, "1.0")

    encryption_data = {
        'ciphertexts': ciphertexts,
        'bcc_commitment': bcc_commitment,
        'commitment_key': commitment_key,
        'recipient_digests_signature': recipient_digests_signature,
        'public_key': public_key,
        'recipient_ciphertexts': recipient_ciphertexts,
        'manifest_encrypted': manifest_encrypted,
        'manifest_encrypted_hash': manifest_encrypted_hash,
        'xcha_nonces': xcha_nonces,
    }



    def encode_item(item):

        if isinstance(item, bytes):
            return base64.b64encode(item).decode('utf-8')
        elif isinstance(item, list):
            return [base64.b64encode(i).decode('utf-8') for i in item]
        elif isinstance(item, X25519PublicKey):
            public_key_bytes = item.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            return base64.b64encode(public_key_bytes).decode('utf-8')
        else:
            return item

    encryption_data_encoded = {key: encode_item(value) for key, value in encryption_data.items()}

    sendmail(bcc_address, cc_address, encryption_data_encoded, from_address, to_address,password=password)
    return jsonify({'message': 'Mail data stored successfully and encryption data sent to server'})


def decode_item(item):
        if isinstance(item, str):
            return base64.b64decode(item.encode('utf-8'))
        elif isinstance(item, list):
            return [base64.b64decode(i.encode('utf-8')) for i in item]
        else:
            return item

def sendmail(bcc_address=None, cc_address=None, encryption_data=None, from_address=None, to_address=None, subject=None, content=None, password=None,
             encryption_method=None):
    headers = {'Content-Type': 'application/json'}

    payload = {
        'from': from_address,
        'to': to_address,
        'subject': subject,
        'content': content,
        'password': password,
        'cc': cc_address,
        'bcc': bcc_address,
        'encryption_data': encryption_data,
    }

    try:
        response = requests.post(url + '/send_mail_with_sender', json=payload, headers=headers, verify=False)
        response.raise_for_status()
        print(response.json()['message'])
    except requests.RequestException as e:
        print(f"HTTP request failed: {e}")


@app.route('/receive_mail_with_receiver', methods=['POST'])
def receive_mail_with_receiver():
    data = request.form.to_dict()



    payload = {'username': current_user, 'password': current_passphrase}
    print(payload)
    response = requests.post(url + 'receive_mail_with_receiver', json=payload, verify=False)
    if response.status_code != 200:
        return 'Failed to retrieve emails', 400

    mails = response.json()

    decrypted_mails = []
    for mail in mails:
        sender = mail['sender']
        receiver = mail['receiver']
        cc = mail['cc']
        bcc = mail['bcc']
        date = mail['date']

        encryption_data = mail['encryption_data']

        public_key = x25519.X25519PublicKey.from_public_bytes(read_from_file(current_user, 'public_email_x25519.bin'))

        # 解码 encryption_data
        encryption_data_decoded = {key: decode_item(value) for key, value in encryption_data.items()}

        # 读取接收者的私钥
        private_key_bytes = read_from_file(current_user, 'private_email_x25519.bin')
        private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)

        # 解密邮件
        decrypted_pieces = decrypt_email(
            encryption_data_decoded['ciphertexts'],
            encryption_data_decoded['recipient_ciphertext'],  # 使用对应的 recipient_ciphertext
            x25519.X25519PublicKey.from_public_bytes(encryption_data_decoded['public_key']),
            private_key,
            public_key,
            encryption_data_decoded['manifest_encrypted'],
            encryption_data_decoded['manifest_encrypted_hash'],
            encryption_data_decoded['bcc_commitment'],
            '1.0',  # 假设使用版本 1.0
            encryption_data_decoded['xcha_nonce'],  # 使用对应的 xcha_nonce
            encryption_data['user_ids'],  # 直接使用 user_ids 字符串

        )

        decrypted_mail = {
            'sender': sender,
            'receiver': receiver,
            'cc': cc,
            'bcc': bcc,
            'date': date,
            'subject': decrypted_pieces[0].decode('utf-8'),
            'content': decrypted_pieces[1].decode('utf-8')
        }
        decrypted_mails.append(decrypted_mail)

    return jsonify(decrypted_mails)




if __name__ == '__main__':
    app.run(port=5000)
