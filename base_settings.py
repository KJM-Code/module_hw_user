from flask import Blueprint
Main = Blueprint('Users',__name__,url_prefix="/user",template_folder='templates',static_folder='static')
database_binding = 'users'
Schema = 'users'

blueprints = [Main]
