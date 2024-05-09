from datetime import datetime

import Config

pg_database = Config.get_pg_database()
pg_user = Config.get_pg_user()
pg_password = Config.get_pg_password()
pg_host = Config.get_pg_host()
pg_port = Config.get_pg_port()

import psycopg2
from cryptography.hazmat.primitives.asymmetric import x25519

from email import message_from_bytes

import datetime
import json


class RelayerHandler:
    def __init__(self, pg_database, pg_user, pg_password, pg_host, pg_port):
        self.conn = psycopg2.connect(database=pg_database, user=pg_user, password=pg_password, host=pg_host,
                                     port=pg_port)

    async def handle_DATA(self, server, session, envelope):
        mail_from = envelope.mail_from
        rcpt_tos = envelope.rcpt_tos
        msg = message_from_bytes(envelope.content)

        with self.conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM public.mail")
            sum = cur.fetchone()

            email_id = sum[0] + 1
            cur.execute("""
                INSERT INTO public.mail (id, date, mime_version, recipient, sender, subject)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                email_id,
                msg.get('Date') if msg.get('Date') is not None else datetime.datetime.now(),
                msg.get('MIME-Version'),
                ', '.join(rcpt_tos),
                mail_from,
                msg.get('Subject'),
            ))

            if msg.is_multipart():
                for part in msg.get_payload():
                    body = part.get_payload(decode=True).decode()
                    content_type = part.get_content_type()
                    content_transfer_encoding = part.get('Content-Transfer-Encoding')
                    cur.execute("""
                        INSERT INTO public.email_parts (email_id, content_type, content_transfer_encoding, body)
                        VALUES (%s, %s, %s, %s)
                    """, (
                        email_id,
                        content_type,
                        content_transfer_encoding,
                        body
                    ))
            else:
                body = msg.get_payload(decode=True).decode()
                cur.execute("""
                    INSERT INTO public.email_parts (email_id, body)
                    VALUES (%s, %s)
                """, (
                    email_id,
                    body
                ))

            self.conn.commit()

            # Retrieve public keys and user IDs for the recipients
            user_ids, public_keys = self.get_user_ids_and_public_keys(rcpt_tos)

            # Read sender's private key for encryption
            sender_device_private_key = self.read_from_file(mail_from, 'private_email_x25519.bin')
            sender_device_private_key = x25519.X25519PrivateKey.from_private_bytes(sender_device_private_key)

            # Encrypt the email content
            subject = msg.get('Subject')
            content = msg.get_payload(decode=True).decode() if not msg.is_multipart() else "Multipart email content"
            pieces = [subject, content]
            ciphertexts, bcc_commitment, commitment_key, recipient_digests_signature, public_key, recipient_ciphertexts, manifest_encrypted, manifest_encrypted_hash, xcha_nonces = self.main_encrypt(
                pieces, [], public_keys, user_ids, 1.0, sender_device_private_key
            )

            # Store encryption data in the database
            encryption_data_json = json.dumps({
                'ciphertexts': ciphertexts,
                'bcc_commitment': bcc_commitment,
                'commitment_key': commitment_key,
                'recipient_digests_signature': recipient_digests_signature,
                'public_key': public_key,
                'recipient_ciphertexts': recipient_ciphertexts,
                'manifest_encrypted': manifest_encrypted,
                'manifest_encrypted_hash': manifest_encrypted_hash,
                'xcha_nonces': xcha_nonces,
                'user_ids': user_ids
            })

            cur.execute("""
                INSERT INTO public.email_parts (email_id, content_type, content_transfer_encoding, body)
                VALUES (%s, %s, %s, %s)
            """, (
                email_id,
                'application/json',
                'base64',
                encryption_data_json
            ))

            self.conn.commit()

        return '250 OK'