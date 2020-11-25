import flask
from flask import render_template, flash, redirect, request, url_for, g, jsonify
from flask_login import login_user, logout_user, current_user
from werkzeug.urls import url_parse

from app.forms import LoginForm, RegistrationForm, EditProfileForm
from app import app, db, csrf
from app.models import User, Post
from flask_login import login_required
from datetime import datetime


@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        print("User is authenticated")
        db.session.commit()
    else:
        authTokenHeader = request.headers.get('Session')
        if authTokenHeader:
            user = User.verify_auth_token(authTokenHeader)
            if user:
                login_user(user)


@app.route('/')
@app.route('/index')
@login_required
def index():
    posts = posts = Post.query.all()
    return render_template('index.html', title='Home', posts=posts)


# Route for debugging purposes
@app.route('/message', methods=['POST'])
def message():
    print("Received connection on /message route with message: ", request.json['message'])

    return {"message": request.json['message']}


@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = [
        {'author': user, 'body': 'Test post #1'},
        {'author': user, 'body': 'Test post #2'}
    ]
    return render_template('user.html', user=user, posts=posts)


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', title='Edit Profile',
                           form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    print(form.hidden_tag())

    if flask.request.method == 'POST':
        print("POST")
    elif flask.request.method == 'GET':
        # Return CSRF token for proper authentication
        print("GET")
        return form.hidden_tag()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            print('Invalid username or password')
            return redirect('/login')
        login_user(user, remember=form.remember_me.data)
        print("Authenticated: " + user.username)
        token = user.generate_auth_token()
        return jsonify({"message": "Login succeeded", 'token': token.decode('ascii')})
    if form.errors:
        print("Errors:", form.errors)
    return {"message": "Login failed"}


@app.route('/verifyLogin')
@login_required
def verify_login():
    print(request.headers)
    authTokenHeader = request.headers.get('Session')
    print("Auth token:" + authTokenHeader)
    if authTokenHeader:
        user = User.verify_auth_token(authTokenHeader)
        if user:
            return {"success": user.is_authenticated}
    else:
        return {"message": "there was an error.", "error": "you failed"}


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect('/index')
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect('/login')
    return render_template('register.html', title='Register', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/index')
