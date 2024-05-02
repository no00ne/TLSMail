from datetime import datetime

import Config
import psycopg2
from email import message_from_bytes

pg_database = Config.get_pg_database()
pg_user = Config.get_pg_user()
pg_password = Config.get_pg_password()
pg_host = Config.get_pg_host()
pg_port = Config.get_pg_port()


class RelayerHandler:
    def __init__(self):
        self.conn = psycopg2.connect(database=pg_database, user=pg_user, password=pg_password, host=pg_host,
                                     port=pg_port)

    async def handle_DATA(self, server, session, envelope):
        mail_from = envelope.mail_from
        rcpt_tos = envelope.rcpt_tos
        msg = message_from_bytes(envelope.content)

        with self.conn.cursor() as cur:
            cur.execute("""
                Select count(*) from public.mail
            """)
            sum = cur.fetchone()
            cur.execute("""
                INSERT INTO public.mail (Id, date, mime_version, recipient, sender, subject)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                sum[0] + 1,
                msg.get('Date') if msg.get('Date') is not None else datetime.now(),
                msg.get('MIME-Version'),
                ', '.join(rcpt_tos),
                mail_from,
                msg.get('Subject'),
            ))
            self.conn.commit()

            if msg.is_multipart():
                for part in msg.get_payload():
                    body = part.get_payload(decode=True).decode()
                    content_type = part.get_content_type()
                    content_transfer_encoding = part.get('Content-Transfer-Encoding')
                    cur.execute("""
                        INSERT INTO email_parts (email_id, content_type, content_transfer_encoding, body)
                        VALUES (%s, %s, %s, %s)
                    """, (
                        sum[0] + 1,
                        content_type,
                        content_transfer_encoding,
                        body
                    ))
                    self.conn.commit()

            else:
                body = msg.get_payload()
                cur.execute("""
                    INSERT INTO email_parts (email_id, body)
                    VALUES (%s, %s)
                """, (
                    sum[0] + 1,
                    body
                ))
                self.conn.commit()

        return '250 OK'
