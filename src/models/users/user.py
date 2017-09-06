import uuid
import sqlite3
from flask.ext.login import login_manager

from src.common.database import db
from src.common.utils import Utils
import src.models.users.errors as UserErrors
import src.models.users.constants as UserConstants



class User(db.Model):
    __tablename__ = 'users'

    _id =db.Column(db.String(80), primary_key=True)
    username = db.Column(db.String(80))
    email = db.Column(db.String(80))
    password = db.Column(db.String(80))
    permission = db.Column(db.Integer)
    active = db.Column(db.Integer)
    authenticated = db.Column(db.Integer)
    def __init__(self, username, email, password, active, permission, authenticated, _id=None):
        self.username = username
        self.email = email
        self.password = password
        self.permission = 3 if username == 'administrator' else permission
        self.active = True if username == 'administrator' else active
        self._id = uuid.uuid4().hex if _id is None else _id
        self.authenticated=authenticated

    def __repr__(self):
        return "<User {}>".format(self.email)

    @staticmethod
    def is_login_valid(username, password):
        """
        This method verifies that an e-mail/password combo ( as sent by the site forms) is valid or not.
        checks that the e-mail exists, and that the password associated to that e-mail is correct.
        :param email: The user's email
        :param password: A sha512 hashed password
        :return: True if valid, False if otherwise
        """
        user_data = User.query.filter_by(username=username).first() #Password in sha512 - >pbkdf2_sha512
        if user_data is None:
            raise UserErrors.UserNotExistsError("Your user does not exist.")
        if not user_data['active']:
            raise UserErrors.UserDisabledError("Your user is disabled.")
        if not Utils.check_hashed_password(password, user_data['password']):
            raise UserErrors.IncorrectPasswordError("Your password was wrong.")


        return True

    @staticmethod
    def register_user(username, email, password, active, permission):
        """
        This method registers a user using e-mail and password.
        The password already comes hashed as a sha-512
        :param email: user's e-mail (might be invalid
        :param password: sha512-hsahed password
        :return: True if registered successfully, or False otherwise(exceptions can also be raised)
        """
        user_data = User.query.filter_by(email=email).first()

        if user_data is not None:
            raise UserErrors.UserAlreadyRegisteredError("The e-mail you used to register already exists.")
        if not Utils.email_is_valid(email):
            raise UserErrors.InvalidEmailError("The e-mail does not have the right format.")
        user_data = User.query.filter_by(username=username).first()
        if user_data is not None:
            raise UserErrors.UserAlreadyRegisteredError("The username you used to register already exists.")
        User(username,email, Utils.hash_password(password), active, permission, False).save_to_db()
        return True

    def save_to_db(self):
        db.session.add(self)


    def json(self):
        return {
            "_id": self._id,
            "username":self.username,
            "email": self.email,
            "password": self.password,
            "active":self.active,
            "permission":self.permission,
            "authenticated":self.authenticated
        }

    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter_by(email=email).first()
        #return cls(**db.find_one(UserConstants.COLLECTION,{'email': email}))

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()
        #return cls(**db.find_one(UserConstants.COLLECTION,{'username': username}))

    @classmethod
    def find_all(cls):
        return User.query.all()
        #return [cls(**elem) for elem in db.find(UserConstants.COLLECTION,{})]

    def get_alerts(self):
        return Alert.find_by_user_email(self.email)

    @classmethod
    def find_by_id(cls, _id):
        return User.query.filter_by(_id=_id).first()

    def deactivate(self):
        self.active = False
        self.save_to_db()

    def activate(self):
        self.active = True
        self.save_to_mdb()



    def is_active(self):
        return self.active

    def get_id(self):
        return self._id

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False

    #def get_users(self):
    #return User.find_all()
    def save_to_db(self):

        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):

        db.session.delete(self)
        db.session.commit()

    @classmethod
    def find_by_username(cls, username):

        return cls.query.filter_by(username=username).first()  # SELECT * FROM items WHERE name = name LIMIT 1