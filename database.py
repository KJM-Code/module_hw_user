from imports.database import db
from flask_login import UserMixin
from .base_settings import Schema

class SYS_USERS(UserMixin, db.Model):
    __table_args__ = {'sqlite_autoincrement': True,
                      "schema": Schema}
    SYSUR_AUTO_KEY = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True,nullable=False)
    password = db.Column(db.String,nullable=False)

    def get_id(self):
        return self.SYSUR_AUTO_KEY
    def get_username(self):
        return self.username