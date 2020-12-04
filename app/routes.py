import json

import flask
from flask import render_template, flash, redirect, request, url_for, g, jsonify
from flask_login import login_user, logout_user, current_user
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename

from PIL import Image
from io import BytesIO
import base64

from app.forms import LoginForm, RegistrationForm, EditProfileForm, CreatePostForm
from app import app, db, csrf
from app.models import User, Post, Image
from flask_login import login_required
from datetime import datetime

import uuid


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


@app.route('/testpage')
def testpage():
    posts = posts = Post.query.all()
    return render_template('index.html', title='Home', posts=posts)


@app.route('/')
@app.route('/get_all_posts')
@login_required
def get_all_posts():
    posts = Post.query.all()

    postsArray = []
    for post in posts:
        user = User.query.get(post.user)
        postsArray.append({"username": user.username, "content": post.content})
    print(postsArray)
    response = json.dumps({
        "response": postsArray,
        "status": 200,
        "mimetype": 'application/json'
    })
    print(json.loads(response))

    return response


# Route for debugging purposes
@app.route('/message', methods=['POST'])
def message():
    print("Received connection on /message route with message: ", request.json['message'])

    return {"message": request.json['message']}


@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(username=username)
    print("Get posts: ", posts)
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

    requestDecoded = request.data.decode()
    print(requestDecoded)

    if flask.request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user is None or not user.check_password(form.password.data):
                print('Invalid username or password')
                return jsonify({"message": 'Invalid username or password'}), 404
            login_user(user, remember=form.remember_me.data)
            print("Authenticated: " + user.username)
            token = user.generate_auth_token()
            return jsonify({"message": "Login succeeded", 'token': token.decode('ascii'), "status": 200})
        if form.errors:
            print("Errors:", form.errors)
        return {"message": "Login failed"}, 301
    elif flask.request.method == 'GET':
        # Return CSRF token for proper authentication
        return form.hidden_tag(), 200


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    requestDecoded = request.data.decode()
    print(requestDecoded)

    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        print("Registered new user: ", user.username)
        token = user.generate_auth_token()
        return {"message": "signup successful", "token": token.decode('ascii')}
    return {"message": "signup failed"}, 301


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/index')


# create_post
@app.route('/create_post', methods=["POST"])
@login_required
def create_post():
    form = CreatePostForm()

    form.username = current_user.username

    requestDecoded = request.data.decode()
    print(requestDecoded)

    if form.validate_on_submit():
        new_post = Post(username=current_user.username, content=form.content)
        db.session.add(new_post)
        db.session.commit()
        return {"message": "You've added a post to XY.", "status": 200}
    return {"message": "Could not add post."}, 300


# create post form
# verify form
# set username from current_user
# make post model and add/commit to db


# Upload image:
# use request.files for access.
#
@app.route('/upload_image', methods=['POST'])
@login_required
def upload_image():
    print("Upload image request")

    filename = request.form.get('file')
    imagedata = request.form.get('attachment')
    print("File: ", imagedata)

    if request.method == 'POST' and filename is not None and imagedata is not None:
        # check if the post request has the file part
        #mimetype = file.mimetype

        uid = uuid.uuid4().__str__()
        print("Added image to database with id: ", uid)
        img = Image(img=imagedata, mimetype=".png", name=filename, id=uid)

        db.session.add(img)
        db.session.commit()

        return {"message": "Image has been uploaded", "id": uid}, 200
    else:
        return {"message": "Failed to upload image"}, 300


@app.route('/get_image', methods=['GET'])
@login_required
def get_image():
    imageId = request.headers.get('imageID')
    print("Request for image: ", imageId)
    if imageId is not None:
        print("Checking database for id:", imageId)

        img = Image.query.get(imageId)
        result = {"message":"Here is your image", "imageData": img.img, "id":imageId}
        print(result)
        return result, 200
    return {"message": "No image id found."}, 300
