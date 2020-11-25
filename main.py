# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# [START gae_python37_app]
import os
from PIL import Image
from flask import Flask, render_template, url_for, flash, redirect, request, jsonify
from flask_mail import Message, Mail
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, PasswordField, BooleanField, SelectField, IntegerField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from flask_wtf.file import FileField, FileAllowed
from os import urandom
from google.cloud import storage

db_user = os.environ.get('CLOUD_SQL_USERNAME')
db_password = os.environ.get('CLOUD_SQL_PASSWORD')
db_name = os.environ.get('CLOUD_SQL_DATABASE_NAME')
db_connection_name = os.environ.get('CLOUD_SQL_CONNECTION_NAME')

#CLOUD_STORAGE_BUCKET = os.environ.get('CLOUD_STORAGE_BUCKET')


def gen_connection_string():
    if os.environ.get('GAE_ENV') == 'standard':
        # If deployed, use the local socket interface for accessing Cloud SQL
        unix_socket = '/cloudsql/{}'.format(db_connection_name)
        engine_url = 'mysql+pymysql://{}:{}@/{}?unix_socket={}'.format(
            db_user, db_password, db_name, unix_socket)
        return engine_url
    else:
        # If running locally, use the TCP connections instead
        # Set up Cloud SQL Proxy (cloud.google.com/sql/docs/mysql/sql-proxy)
        # so that your application can use 127.0.0.1:3306 to connect to your
        # Cloud SQL instance
        # host = '127.0.0.1'
        # engine_url = 'mysql+pymysql://{}:{}@{}/{}'.format(
        #     db_user, db_password, host, db_name)
        engine_url = 'sqlite:///site.db'
        return engine_url

app = Flask(__name__)
app.config['SECRET_KEY'] = 'e2a01ccf500c0c4b5a4f554346c839bf'
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USERNAME"] = 'costumer.contact.request@gmail.com'
app.config["MAIL_PASSWORD"] = 'shahedinetherlands1377'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = gen_connection_string()
CLOUD_STORAGE_BUCKET = 'amir-nl'

mail = Mail(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)


                ################################Forms#####################################       
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class ContactForm(FlaskForm):
    fullname = StringField("Full Name", validators=[DataRequired()])
    phonenumber = StringField("Phone number", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField("Post")

class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')


class LoginForm(FlaskForm):
    email1 = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit1 = SubmitField('Login')

class Create(FlaskForm):
    category = SelectField('Category', choices=[('BestSeller', 'BestSeller'),
                                                ('Nature', 'Nature'),
                                                ('City', 'City'),
                                                ("Children", 'Children'),
                                                ('Modern', 'Modern'),
                                                ('Classic', 'Classic')])
    title = StringField('Title')
    content = TextAreaField('Content')
    price = StringField('Price')
    sale = IntegerField('Sale')
    picture = FileField('Upload an image', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Post')

class Search(FlaskForm):
    keywords = StringField('Keywords',
                          validators=[DataRequired()])
    submit2 = SubmitField('Search')
                ################################Models#####################################


class User(db.Model, UserMixin):
    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return "User(%s ,%s)" % (self.username, self.email)


class Post(db.Model):
    __tablename__ = 'Post'
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(20))
    title = db.Column(db.String(120))
    content = db.Column(db.Text)
    price = db.Column(db.String(10))
    sale = db.Column(db.Integer)
    image_file = db.Column(db.String(20), default='default.png')

    def __repr__(self):
        return "Post(%s, %s, %s)" % (self.category, self.title, self.Price)


                ################################Routes#####################################
@app.route('/')
def home():
    return render_template('Intro.html')

@app.route('/decorations', methods=['GET','POST'])
def decorations():
    form = ContactForm()
    form2 = Search()
    if form.validate_on_submit():
        msg = Message("Messsage from" + form.fullname.data, sender='costumer.contact.request@gmail.com', recipients=['fariborzvakili@yahoo.com'])
        msg.body = """
      From: %s %s <%s>

      %s
      """ % (form.fullname.data, form.phonenumber.data, form.email.data, form.content.data)
        mail.send(msg)
        flash('Your message has been submitted', 'success')
        return redirect(url_for('decorations'))

    return render_template('Decorations.html', title="Home", form=form, form2=form2)

@app.route('/Offers', methods=['GET','POST'])
@login_required
def Offers():
    return "No Offers Right Now, Check Your Emails for Promotion Notifications"

@app.errorhandler(401)
def custom_401(error):
    return "You Need To Be Logged In"
    
@app.route('/ContactUs', methods=['GET','POST'])
def ContactUs():
    form = ContactForm()
    form2 = Search()
    #
    return render_template('ContactUs.html', title="ContactUs", form=form, form2 = form2)

@app.route('/Login', methods=['GET','POST'])
def account():
    if current_user.is_authenticated:
        return redirect(url_for('decorations'))
    form = ContactForm()
    form1 = LoginForm()
    form2 = Search()
    if form1.validate_on_submit():
        user = User.query.filter_by(email=form1.email1.data).first()
        if user and bcrypt.check_password_hash(user.password, form1.password.data):
            login_user(user, remember=form1.remember.data)
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title="Login", form=form, form1=form1, form2 = form2)

@app.route('/register', methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('decorations'))
    form1 = RegistrationForm()
    form = ContactForm()
    form2 = Search()
    if form1.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form1.password.data).decode('utf-8')
        user = User(username=form1.username.data, email=form1.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('account'))
    return render_template('signup.html', title="Sign Up", form=form, form1=form1, form2 = form2)

@app.route('/Logout')
def logout():
    logout_user()
    return redirect(url_for('decorations'))


def save_picture(form_picture):
    if form_picture:
        random_hex = urandom(8).hex()
        _, f_ext = os.path.splitext(form_picture.filename)
        picture_fn = random_hex + f_ext

        gcs = storage.Client()
        bucket = gcs.get_bucket(CLOUD_STORAGE_BUCKET)       #set the value in app.yaml
        blob = bucket.blob(picture_fn)                  #takes in the filename

        blob.upload_from_string(
        form_picture.read(),
        content_type=form_picture.content_type
        )
        return blob.public_url

@app.route('/CreatePost/amirshahedi', methods=['GET','POST'])
def CreatePost():
    form = Create()
    if form.validate_on_submit():
        # uploaded_file = request.files.get('file')
        image_url = save_picture(form.picture.data)
        post = Post(category=form.category.data, title=form.title.data, content=form.content.data, price=form.price.data, sale=form.sale.data, image_file = image_url )
        db.session.add(post)
        db.session.commit()
    return render_template('CreatePost.html', title="CreatePost", form1=form)

@app.route('/Modern')
def Modern():
    posts = Post.query.filter_by(category='Modern').all()
    form2 = Search()
    return render_template('Posts.html', title="Modern", posts=posts, form2 = form2)

@app.route('/BestSeller')
def BestSeller():
    posts = Post.query.filter_by(category='BestSeller').all()
    form2 = Search()
    return render_template('Posts.html', title="BestSeller", posts=posts, form2 = form2)

@app.route('/Nature')
def Nature():
    posts = Post.query.filter_by(category='Nature').all()
    form2 = Search()
    return render_template('Posts.html', title="Nature", posts=posts, form2 = form2)

@app.route('/City')
def City():
    posts = Post.query.filter_by(category='City').all()
    form2 = Search()
    return render_template('Posts.html', title="City", posts=posts, form2 = form2)

@app.route('/Children')
def Children():
    # posts = Post.query.filter_by(category='Children').all()
    posts = Post.query.all()
    form2 = Search()
    return render_template('Posts.html', title="Children", posts=posts, form2 = form2)

@app.route('/Classic')
def Classic():
    posts = Post.query.filter_by(category='Classic').all()
    form2 = Search()
    return render_template('Posts.html', title="Classic", posts=posts, form2 = form2)

def rank_post(string, title):
    words_title = []
    words_string = []
    repeat = 0
    word = ''

    for i in title:
        if (i == " "):
            word = word.lower()
            words_title.append(word)
            word = ''
        else:
            word = word + i
    word = word.lower()
    words_title.append(word)

    word ='' 
    for j in string:
        if (j == " "):
            word = word.lower()
            words_string.append(word)
            word = ''
        else:
            word = word + j

    word = word.lower()
    words_string.append(word)

    for term1 in words_string:
        for term2 in words_title:
            if (term1 == term2):
                repeat = repeat + 1
    return repeat

@app.route('/Search', methods=['GET','POST'])
def Find():
    form2 = Search()
    if form2.validate_on_submit():
        posts = Post.query.all()
        results=[]
        for post in posts:
            rank = rank_post(form2.keywords.data, post.title)
            results.append((post, rank))
        results = sorted(results, key=lambda item: item[1], reverse=True)
    return render_template('SearchResult.html', title="Search", results=results, form2 = form2)
if __name__ == '__main__':
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.
    # db.create_all()
    app.run(host='127.0.0.1', port=8081, debug=True)
# [END gae_python37_app]
