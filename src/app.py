from flask import Flask
from flask import render_template
from flask.ext.login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from src.common.database import db

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'


app.config.from_object('config')
app.secret_key = "123"

@app.before_first_request
def create_tables():

    db.create_all()

@app.route('/')
def home():
    return render_template('home.jinja2')

from src.models.users.views import user_blueprint
from src.models.alerts.views import alert_blueprint
from src.models.stores.views import store_blueprint

app.register_blueprint(user_blueprint, url_prefix="/users")
app.register_blueprint(alert_blueprint, url_prefix="/alerts")
app.register_blueprint(store_blueprint, url_prefix="/stores")