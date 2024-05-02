import psycopg2
from aiosmtpd.smtp import AuthResult, LoginPassword
from psycopg2 import pool

import Config

pg_host = Config.get_pg_host()
pg_port = Config.get_pg_port()
pg_database = Config.get_pg_database()
pg_user = Config.get_pg_user()
pg_password = Config.get_pg_password()


class Authenticator:
    def __init__(self):
        self.conn_pool = psycopg2.pool.SimpleConnectionPool(1, 20, host=pg_host, database=pg_database, user=pg_user,
                                                            password=pg_password)

    def __call__(self, server, session, envelope, mechanism, auth_data):
        fail_nothandled = AuthResult(success=False, handled=False)
        if mechanism not in ("LOGIN", "PLAIN"):
            return fail_nothandled
        if not isinstance(auth_data, LoginPassword):
            return fail_nothandled
        username = auth_data.login.decode()
        password = auth_data.password.decode()
        # Connect to the database
        conn = self.conn_pool.getconn()
        try:
            with conn.cursor() as cur:
                # Query the password of the user
                cur.execute("SELECT password FROM public.user WHERE username = %s", (username,))
                result = cur.fetchone()
                if result is not None and result[0] == password:
                    return AuthResult(success=True)
        finally:
            self.conn_pool.putconn(conn)
        return fail_nothandled
