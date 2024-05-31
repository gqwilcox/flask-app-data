from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
# from werkzeug.security import generate_password_hash, check_password_hash
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import os
from sqlalchemy.exc import IntegrityError


app = Flask(__name__)

app.config['SECRET_KEY'] = os.urandom(24).hex()  # Generate a random secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

ph = PasswordHasher()

class User(UserMixin, db.Model):

    # __tablename__ = 'user'  # Explicitly specify the table name

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    salt = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):

    return User.query.get(int(user_id))


@app.context_processor
def inject_user():

    return dict(current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user:
            try:
                if ph.verify(user.password, password):
                    login_user(user)
                    return redirect(url_for('home'))
            except VerifyMismatchError:
                flash('Login Unsuccessful. Please check username and password', 'danger')
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    error_message = None  # Initialize error message

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        try:
            # Attempt to create a new user
            hashed_password = ph.hash(password)
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            # If username is already taken, set the error message
            error_message = 'Username is already taken. Please choose another one.'

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


