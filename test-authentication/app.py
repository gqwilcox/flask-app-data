from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import os
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)

app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

ph = PasswordHasher()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    phonenumber = db.Column(db.String(150), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    activationcode = db.Column(db.String(150), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.context_processor
def inject_user():
    return dict(current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user:
            try:
                if ph.verify(user.password, password):
                    login_user(user)
                    return redirect(url_for('home'))
            except VerifyMismatchError:
                flash('Login Unsuccessful. Please check email and password', 'danger')
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():

    error_message = None

    if request.method == 'POST':
        name = request.form.get('name')
        phonenumber = request.form.get('phonenumber')
        activationcode = request.form.get('activationcode')
        email = request.form.get('email')
        password = request.form.get('password')

        try:
            hashed_password = ph.hash(password)
            new_user = User(name=name, phonenumber=phonenumber, activationcode=activationcode, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))

        except IntegrityError:
            error_message = 'An account with this email already exists. Please choose another one.'

    return render_template('register.html', error_message=error_message)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def home():
    if current_user.is_authenticated:
        return render_template('base.html')
    else:
        return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
