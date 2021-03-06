from flask import Blueprint
from flask import redirect, url_for
from flask import render_template
from flask import request
from flask import session
from flask.ext.login import login_required

from src.models.alerts.alert import Alert
from src.models.items.item import Item
import src.models.users.decorators as user_decorators

alert_blueprint = Blueprint('alerts', __name__)


@alert_blueprint.route('/')
@login_required
def index():
    return "This is the alerts index"

@alert_blueprint.route('/new', methods=['GET', 'POST'])
@login_required #redirects the user to users.login
def create_alert():
    if request.method =='POST':
        name = request.form['name']
        url = request.form['url']
        price_limit = float(request.form['price_limit'])
        item=Item(name,url)


        item.save_to_mongo()


        alert= Alert(session['email'],  price_limit, item._id)
        alert.load_item_price()


    return render_template('alerts/new_alert.jinja2')


@alert_blueprint.route('/deactivate/<string:alert_id>')
@login_required
def deactivate_alert(alert_id):
    Alert.find_by_id(alert_id).deactivate()
    return redirect(url_for('users.user_alerts'))

@alert_blueprint.route('/activate/<string:alert_id>')
@login_required
def activate_alert(alert_id):
    Alert.find_by_id(alert_id).activate()
    return redirect(url_for('users.user_alerts'))

@alert_blueprint.route('/delete/<string:alert_id>')
@login_required
def delete_alert(alert_id):
    Alert.find_by_id(alert_id).delete()
    return redirect(url_for('users.user_alerts'))

@alert_blueprint.route('/<string:alert_id>')
@login_required
def get_alert_page(alert_id):
    alert = Alert.find_by_id(alert_id)
    return render_template('alerts/alert.jinja2', alert=alert)


@alert_blueprint.route('/check_price/<string:alert_id>')
def check_alert_price(alert_id):
    Alert.find_by_id(alert_id).load_item_price()
    return redirect(url_for('.get_alert_page', alert_id=alert_id))
