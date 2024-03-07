from flask import Flask, render_template, redirect, url_for, flash, session, request, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FloatField, DateField, TimeField, \
    SelectField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Email, Length
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy.orm import joinedload

from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root@localhost/tasky'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'  # Change this to a secure random key
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.init_app(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255))
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    due_date = db.Column(db.Date)
    priority = db.Column(db.Integer, default=0)  # 0: Low, 1: Medium, 2: High
    status = db.Column(db.String(20), default='Pending')  # Options: Pending, In Progress, Completed, Deferred
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('tasks', lazy=True))
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(),
                           onupdate=db.func.current_timestamp())


class TaskAssignee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    assigned_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    task = db.relationship('Task', backref=db.backref('assignees', lazy=True))
    user = db.relationship('User', backref=db.backref('assigned_tasks', lazy=True))


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    task = db.relationship('Task', backref=db.backref('comments', lazy=True))
    user = db.relationship('User', backref=db.backref('comments', lazy=True))


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')


class TaskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=255)])
    description = TextAreaField('Description')
    due_date = DateField('Due Date')
    priority = SelectField('Priority', choices=[('0', 'Low'), ('1', 'Medium'), ('2', 'High')])
    status = SelectField('Status',
                         choices=[('Pending', 'Pending'), ('In Progress', 'In Progress'), ('Completed', 'Completed'),
                                  ('Deferred', 'Deferred')])
    submit = SubmitField('Create Task')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template('index.html')


# 404 error handler
@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('sign_up'))

        # Check if the user already exists in the database
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please use a different email.', 'error')
            return redirect(url_for('sign_up'))

        # Hash the password
        password_hash = generate_password_hash(password)

        # Create a new user with the provided email and hashed password
        new_user = User(email=email, password_hash=generate_password_hash(password))

        # Add the new user to the database
        new_user = User(username=username, email=email, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('sign_in'))

    return render_template('login.html')


@app.route('/sign_in', methods=['GET', 'POST'])
def sign_in():
    if request.method == 'POST':
        email = request.form.get('email')  # Safely retrieve email from form data
        password = request.form.get('password')  # Safely retrieve password from form data

        # Query the database to find a user with the provided email
        user = User.query.filter_by(email=email).first()

        # Check if the user exists and the password matches
        if user and check_password_hash(user.password_hash, password):
            flash('Login successful', 'success')
            return redirect(url_for('home'))  # Redirect to the home page after successful login
        else:
            flash('Invalid email or password', 'error')
            return redirect(url_for('sign_in'))  # Redirect back to the login page if login fails

    # Render the login form template for GET requests
    return render_template('login.html')


# logout route handler
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('sign_in'))


@app.route('/task')
def task():
    return render_template('task.html')


@app.route('/profile')
def profile():
    return render_template('profile.html')


# Ensure this is at the end of your script to run the application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
