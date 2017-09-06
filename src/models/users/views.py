from flask import Blueprint
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask.ext.login import current_user, login_manager
from flask.ext.login import login_required
from flask.ext.login import login_user
from flask.ext.login import logout_user

import src.models.users.errors as UserErrors
import src.models.users.decorators as user_decorators


from src.models.users.user import User

user_blueprint = Blueprint('users', __name__)

@user_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            if User.is_login_valid(username, password):

                user = User.find_by_username(username)
                user.authenticated=True
                user.save_to_db()
                login_user(user, remember=True)

                return redirect(url_for('home'))

        except UserErrors.UserError as e:
            return e.message

    return render_template("users/login.jinja2")


@user_blueprint.route('/register', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        active = False
        permission=1
        try:
            if User.register_user(username,email, password,active,permission):
                #session['email'] = email
                return redirect(url_for('home'))
        except UserErrors.UserError as e:
            return e.message

    return render_template("users/register.jinja2")



@user_blueprint.route('/alerts')
@login_required
def user_alerts():
    user = User.find_by_email(session['email'])
    alerts = user.get_alerts()
    return render_template('users/alerts.jinja2', alerts=alerts)


@user_blueprint.route('/logout')
def logout():
    user = current_user
    user.authenticated = False

    logout_user()
    return redirect(url_for('home'))



@user_blueprint.route('/admin')
@login_required
@user_decorators.requires_roles(3)
def admin():
    users = User.find_all()

    return render_template('users/admin.jinja2', users=users)

@user_blueprint.route('/profile/<string:user_id>')
@login_required
def profile(user_id):
    user=User.find_by_id(user_id)
    return render_template('users/profile.jinja2',user=user)

@user_blueprint.route('/get_user_page/<string:user_id>')
@login_required
@user_decorators.requires_roles(3)
def get_user_page(user_id):
    user = User.find_by_id(user_id)
    return render_template('users/edit_users.jinja2', user=user)


@user_blueprint.route('/deactivate/<string:user_id>')
@login_required
@user_decorators.requires_roles(3)
def deactivate_user(user_id):
    user = User.find_by_id(user_id)
    user.deactivate()

    return render_template('users/edit_users.jinja2', user=user)



@user_blueprint.route('/change_permission/<string:user_id>', methods=['GET', 'POST'])
@login_required
@user_decorators.requires_roles(3)
def change_permission(user_id):
    user = User.find_by_id(user_id)
    user.permission=int(request.form['permission'])
    user.save_to_mongo()
    return render_template('users/edit_users.jinja2', user=user)

@user_blueprint.route('/activate/<string:user_id>')
@login_required
@user_decorators.requires_roles(3)
def activate_user(user_id):
    user = User.find_by_id(user_id)
    user.activate()
    return render_template('users/edit_users.jinja2', user=user)

@user_blueprint.route('/delete/<string:user_id>')
@login_required
@user_decorators.requires_roles(3)
def delete_user(user_id):
    User.find_by_id(user_id).delete()

    return redirect(url_for('users.admin'))

@user_blueprint.route('/deactivate_account/<string:user_id>')
@login_required
def deactivate_account(user_id):
    User.find_by_id(user_id).deactivate()
    return redirect(url_for('home'))

@user_blueprint.route('/create', methods=['GET', 'POST'])
@login_required
@user_decorators.requires_roles(3)
def create_user():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        username = request.form['username']
        permission = int(request.form['permission'])
        active = request.form['active']
        authenticated = False

        try:
            if User.register_user(username,email, password, active, permission):
                return redirect(url_for(".admin"))
        except UserErrors.UserError as e:
            return e.message

    return render_template("users/create_user.jinja2")

#!py



@user_blueprint.route('/check_alerts/<string:user_id>')
def check_user_alerts(user_id):
    pass
