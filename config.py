import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard-to-guess-string'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Microsoft Teams Configuration
    MICROSOFT_CLIENT_ID = os.environ.get('MICROSOFT_CLIENT_ID')
    MICROSOFT_CLIENT_SECRET = os.environ.get('MICROSOFT_CLIENT_SECRET')
    MICROSOFT_TENANT_ID = os.environ.get('MICROSOFT_TENANT_ID')
    
    # Dropbox Configuration
    DROPBOX_CLIENT_ID = os.environ.get('DROPBOX_CLIENT_ID')
    DROPBOX_CLIENT_SECRET = os.environ.get('DROPBOX_CLIENT_SECRET')
    DROPBOX_ACCESS_TOKEN = os.environ.get('DROPBOX_ACCESS_TOKEN')
    DROPBOX_REFRESH_TOKEN = os.environ.get('DROPBOX_REFRESH_TOKEN')

    # SOTI Configuration
    SOTI_SERVER_URL = os.environ.get('SOTI_SERVER_URL')
    SOTI_CLIENT_ID = os.environ.get('SOTI_CLIENT_ID')
    SOTI_CLIENT_SECRET = os.environ.get('SOTI_CLIENT_SECRET')
    SOTI_USERNAME = os.environ.get('SOTI_USERNAME')
    SOTI_PASSWORD = os.environ.get('SOTI_PASSWORD')

    @staticmethod
    def init_app(app):
        pass 