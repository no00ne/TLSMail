import configparser

config = configparser.ConfigParser()
config.read('client.properties')


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


def get_local_pg_host():
    return config['POSTGRESQL']['pg.localhost']


def get_localPassword():
    return config['POSTGRESQL']['pg.localPassword']


def get_flask_host():
    return config['FLASK']['flask.host']


def get_flask_server_url():
    return config['FLASK']['flask.server.url']
