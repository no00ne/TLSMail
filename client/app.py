import datetime
import json
import os
from typing import List, Optional, Tuple

import psycopg2
import requests
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from flask import Flask, render_template
from flask import request, jsonify
from flask_bcrypt import generate_password_hash, check_password_hash

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
url='https://26.26.26.1:5000/'
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
        return  'Both username and password are required!' , 400
    print("test")  # Debugging statement

    hashed_password = generate_password_hash(password).decode('utf-8')
    PUKs.generate_and_store_keys(username)
    public_key_email_bytes = read_from_file(username, 'public_email_x25519.bin')



    try:
        # Convert public_key_email_bytes to a format that can be sent in the request
        files = {
            'username': (None, username),
            'hashed_password': (None, hashed_password),
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


def get_user_ids_and_public_keys(
        conn,
        from_address: str,
        to_address: List[str],
        cc_address: Optional[List[str]] = None,
        bcc_address: Optional[List[str]] = None
) -> Tuple[List[int], List[ed25519.Ed25519PublicKey]]:
    # Collect all relevant addresses into a single list
    addresses = [from_address] + to_address
    if cc_address:
        addresses += cc_address
    if bcc_address:
        addresses += bcc_address

    user_ids = []
    public_keys = []

    with conn.cursor() as cur:
        # Construct the SQL query with placeholders for the addresses
        query = """
            SELECT id, public_key_email_bytes
            FROM public."user"
            WHERE username = ANY(%s)
            ORDER BY id;
        """
        cur.execute(query, (addresses,))
        rows = cur.fetchall()

        for row in rows:
            user_id = row[0]
            public_key_bytes = row[1]
            public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
            user_ids.append(user_id)
            public_keys.append(public_key)

    return user_ids, public_keys
@app.route('/send_mail_with_sender', methods=['POST'])
def send_mail_with_sender():
    data = request.get_json()
    from_address = data['from']
    to_address = data['to']
    cc_address = data.get('cc', [])
    bcc_address = data.get('bcc', [])
    subject = data['subject']
    content = data['content']
    password = data['password']
    pieces = [subject, content]

    conn = get_db_connection()
    user_ids, public_keys = get_user_ids_and_public_keys(conn, from_address, to_address, cc_address, bcc_address)

    sender_device_private_key = read_from_file(from_address, 'private_email_x25519.bin')
    sender_device_private_key = x25519.X25519PrivateKey.from_private_bytes(sender_device_private_key)

    ciphertexts, bcc_commitment, commitment_key, recipient_digests_signature, public_key, recipient_ciphertexts, manifest_encrypted, manifest_encrypted_hash, xcha_nonces = main_encrypt(
        pieces, bcc_address, public_keys, user_ids, 1.0, sender_device_private_key
    )

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

    # Store email and encryption data in the database
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO public.mail (sender, receiver, cc, bcc, date, encryption_data)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            from_address,
            to_address[0],  # Assuming a single receiver for simplicity
            cc_address,
            bcc_address,
            datetime.datetime.now(),
            json.dumps(encryption_data)
        ))
        conn.commit()

    conn.close()
    return jsonify({'message': 'Mail data stored successfully and encryption data sent to server'})

@app.route('/receive_mail_with_receiver', methods=['POST'])
def receive_mail_with_receiver():
    data = request.form
    username = data.get('username')
    password = data.get('password')

    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT sender, receiver, cc, bcc, date, encryption_data
            FROM public.mail
            WHERE receiver = %s
            ORDER BY date DESC
        """, (username,))
        mails = cur.fetchall()

    decrypted_mails = []

    for mail in mails:
        sender = mail[0]
        receiver = mail[1]
        cc = mail[2]
        bcc = mail[3]
        date = mail[4]
        encryption_data = json.loads(mail[5])

        # Read the recipient's private key for decryption
        private_key_bytes = read_from_file(username, 'private_email_x25519.bin')
        private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)

        # Read the sender's public key
        cur.execute("""
            SELECT public_key_email_bytes
            FROM public."user"
            WHERE username = %s
        """, (sender,))
        sender_public_key_bytes = cur.fetchone()[0]
        sender_public_key = x25519.X25519PublicKey.from_public_bytes(sender_public_key_bytes)

        # Decrypt the email
        decrypted_pieces = decrypt_email(
            encryption_data['ciphertexts'],
            encryption_data['recipient_ciphertexts'][0],
            encryption_data['public_key'],
            private_key,
            sender_public_key,
            encryption_data['manifest_encrypted'],
            encryption_data['manifest_encrypted_hash'],
            encryption_data['bcc_commitment'],
            1.0,  # Assuming version 1.0 as used in encryption
            encryption_data['xcha_nonces'][0],
            encryption_data['user_ids'],
            sender_device_key=sender_public_key
        )

        decrypted_mail = {
            'sender': sender,
            'receiver': receiver,
            'cc': cc,
            'date': date,
            'subject': decrypted_pieces[0],
            'content': decrypted_pieces[1]
        }
        decrypted_mails.append(decrypted_mail)

    conn.close()

    return jsonify(decrypted_mails)


if __name__ == '__main__':
    app.run(port=5000)

