from flask import Blueprint
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
import src.models.users.errors as UserErrors
import src.models.users.decorators as user_decorators


from src.models.users.user import User

user_blueprint = Blueprint('users', __name__)

@user_blueprint.route('/login', methods=['GET', 'POST'])
def login_user():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            if User.is_login_valid(email, password):
                session['email'] = email
                return redirect(url_for(".user_alerts"))
        except UserErrors.UserError as e:
            return e.message

    return render_template("users/login.jinja2")


@user_blueprint.route('/register', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        try:
            if User.register_user(username,email, password):
                session['email'] = email
                return redirect(url_for(".user_alerts"))
        except UserErrors.UserError as e:
            return e.message

    return render_template("users/register.jinja2")



@user_blueprint.route('/alerts')
@user_decorators.requires_login
def user_alerts():
    user = User.find_by_email(session['email'])
    alerts = user.get_alerts()
    return render_template('users/alerts.jinja2', alerts=alerts)


@user_blueprint.route('/logout')
def logout_user():
    session['email'] = None
    return redirect(url_for('home'))



@user_blueprint.route('/admin')
@user_decorators.requires_login
def admin():
    users = User.find_all()

    return render_template('users/admin.jinja2', users=users)



@user_blueprint.route('/get_user_page/<string:email>')
@user_decorators.requires_login
def get_user_page(email):
    user = User.find_by_email(email)
    return render_template('users/edit_users.jinja2', user=user)






@user_blueprint.route('/create', methods=['GET', 'POST'])
def create_user():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        username = request.form['username']
        permission = request.form['permission']
        active = request.form['active']

        try:
            if User.register_user(username,email, password, active, permission):
                return redirect(url_for(".admin"))
        except UserErrors.UserError as e:
            return e.message

    return render_template("users/create_user.jinja2")




@user_blueprint.route('/check_alerts/<string:user_id>')
def check_user_alerts(user_id):
    pass