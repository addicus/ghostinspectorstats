from flask.ext.login import LoginManager

from src.app import app
from src.models.users.user import User
from src.common.database import db


login_manager = LoginManager()
login_manager.init_app(app)
db.init_app(app)


@login_manager.user_loader
def user_loader(user_id):
    """Given *user_id*, return the associated User object.

    :param unicode user_id: user_id (email) user to retrieve
    """
    return User.find_by_id(user_id)
app.run(debug=app.config['DEBUG'], port=5000)