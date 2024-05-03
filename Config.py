import configparser

config = configparser.ConfigParser()
config.read('mail.properties')


def get_smtp_host():
    return config['SMTP']['smtp.host']

def get_smtp_server():
    return config['SMTP']['smtp.server']


def get_smtp_port():
    return int(config['SMTP']['smtp.port'])


def get_smtp_username():
    return config['SMTP']['smtp.username']


def get_smtp_password():
    return config['SMTP']['smtp.password']


def get_imap_server():
    return config['IMAP']['imap.server']


def get_imap_port():
    return int(config['IMAP']['imap.port'])


def get_imap_username():
    return config['IMAP']['imap.username']


def get_imap_password():
    return config['IMAP']['imap.password']


def get_pg_host():
    return config['POSTGRESQL']['pg.host']


def get_pg_port():
    return int(config['POSTGRESQL']['pg.port'])


def get_pg_database():
    return config['POSTGRESQL']['pg.database']


def get_pg_user():
    return config['POSTGRESQL']['pg.user']


def get_pg_password():
    return config['POSTGRESQL']['pg.password']

def get_flask_host():
    return config['FLASK']['flask.host']

def get_flask_server_url():
    return config['FLASK']['flask.server.url']