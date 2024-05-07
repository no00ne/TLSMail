import gnupg
import psycopg2
import Config

pg_host = Config.get_pg_host()
pg_port = Config.get_pg_port()
pg_database = Config.get_pg_database()
pg_user = Config.get_pg_user()
pg_password = Config.get_pg_password()
pg_localhost = Config.get_local_pg_host()
pg_localPassword = Config.get_localPassword()


class GPG:
    def __init__(self):
        self.gpg = gnupg.GPG()
        self.gpg.encoding = 'utf-8'

    def generate_key(self, username, passphrase):
        # Connect to the database and insert the public key
        conn = psycopg2.connect(host=pg_host, port=pg_port, database=pg_database, user=pg_user, password=pg_password)

        # check if the user's key already exists
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM public.pkey WHERE username = %s", (username,))
            result = cur.fetchone()
            if result is not None:
                return "Key already exists."

        input_data = self.gpg.gen_key_input(name_email=username, passphrase=passphrase)
        key = self.gpg.gen_key(input_data)

        public_key = self.gpg.export_keys(key.fingerprint)
        private_key = self.gpg.export_keys(key.fingerprint, True, passphrase=passphrase)

        with conn.cursor() as cur:
            cur.execute("DELETE FROM public.pkey WHERE username = %s", (username,))
            conn.commit()
            cur.execute("INSERT INTO public.pkey (username, public_key) VALUES (%s, %s)", (username, public_key))
            conn.commit()
        conn.close()

        conn_local = psycopg2.connect(host=pg_localhost, port=pg_port, database=pg_database, user=pg_user,
                                      password=pg_localPassword)
        with (conn_local.cursor() as cur):
            cur.execute("INSERT INTO public.skey (username, private_key) VALUES (%s, %s)", (username, private_key))
            conn_local.commit()
        return private_key

    def encrypt_message(self, message, recipient):
        conn = psycopg2.connect(host=pg_host, port=pg_port, database=pg_database, user=pg_user, password=pg_password)
        with conn.cursor() as cur:
            cur.execute("SELECT public_key FROM public.pkey WHERE username = %s", (recipient,))
            result = cur.fetchone()
            public_key = result[0]
        recipient_fingerprint = self.gpg.import_keys(public_key).results[0]['fingerprint']
        encrypted_data = self.gpg.encrypt(message, recipient_fingerprint)
        return encrypted_data.data

    def decrypt_message(self, encrypted_data, passphrase):
        decrypted_data = self.gpg.decrypt(encrypted_data, passphrase=passphrase)
        return decrypted_data.data


if __name__ == '__main__':
    # # Initialize the gnupg module
    # gpg = gnupg.GPG()
    #
    # # Generate keys for user1 and user2
    # key_data_user1 = gpg.gen_key_input(name_email='user1', passphrase='user1')
    # key_data_user2 = gpg.gen_key_input(name_email='user2', passphrase='user2')
    #
    # key_user1 = gpg.gen_key(key_data_user1)
    # key_user2 = gpg.gen_key(key_data_user2)
    #
    # # Export the public keys
    # public_key_user1 = gpg.export_keys(key_user1.fingerprint)
    # public_key_user2 = gpg.export_keys(key_user2.fingerprint)
    #
    # # Export the private key of user2
    # private_key_user2 = gpg.export_keys(key_user2.fingerprint, True, passphrase='user2')
    #
    # # Get the fingerprint of User2's public key
    # recipient_fingerprint = gpg.import_keys(public_key_user2).results[0]['fingerprint']
    #
    # # User1 encrypts a message with User2's public key
    # encrypted_data = gpg.encrypt('Hello, User2!', recipients=recipient_fingerprint)
    #
    # # User2 decrypts the message with their own private key
    # decrypted_data = gpg.decrypt(encrypted_data.data, passphrase='user2')
    #
    # print(f"Decrypted message: {decrypted_data.data.decode('utf-8')}")
    pg = GPG()
    pg.generate_key('tony', '123456')
    pg.generate_key('tt', '123456')
    encrypted_data = pg.encrypt_message('Hello, User2!', 'tt')
    encrypted_data = encrypted_data.decode('utf-8')
    decrypted_data = pg.decrypt_message(encrypted_data, '123456')
    print(f"Decrypted message: {decrypted_data.decode('utf-8')}")
