from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, send_file, redirect, url_for, render_template, request, flash, session
from forms import RegistrationForm, LoginForm, ValidateForm, CVForm
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_required, login_user, current_user, logout_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeSerializer
import random
from emailConnection import send_email
from datetime import timedelta
from urllib.parse import urlparse, urljoin

app = Flask(__name__)
app.config['SECRET_KEY'] = 'SECRET KEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///my_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in!'

mail = Mail(app)
# s = URLSafeSerializer('SecretKey')
otp = random.randint(100000,999999)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(120),unique=True)
    password_hash = db.Column(db.String(128))
    CVs = db.relationship('CV', backref='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class CV(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(50), unique=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/reset')
def reset():
    db.session.query(CV).delete()
    db.session.query(User).delete()
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET','POST'])
def register():
    registrationForm = RegistrationForm()
    if request.method == 'POST':
        if registrationForm.validate_on_submit():
            email = registrationForm.email.data
            msg = str(otp)
            send_email(email, msg)
            user = User(username=registrationForm.username.data, email=email)
            session['username'] = user.username
            session['email'] = user.email
            session['password'] = registrationForm.password.data
            return redirect(url_for('validate', registrationForm=registrationForm))

    print(registrationForm.errors.items())
    print(registrationForm.errors)
    return render_template('register.html', form=registrationForm)

@app.route('/validate', methods=['GET','POST'])
def validate():
    validateForm = ValidateForm()
    if validateForm.validate_on_submit():
        if validateForm.otp.data == otp:
            user = User(username=session['username'], email=session['email'])
            user.set_password(session['password'])
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('validate.html', form=validateForm)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

@app.route('/login', methods=['GET','POST'])
def login():
    loginForm = LoginForm()
    if loginForm.validate_on_submit():
        user = User.query.filter_by(username=loginForm.username.data).first()
        if user and user.check_password(loginForm.password.data):
            login_user(user, remember=loginForm.remember.data)
            print('Logged in successfully.')
            if 'next' in session:
                next = session['next']
                if not is_safe_url(next):
                    return redirect(next)
            return redirect(url_for('user', username=user.username))
        else:
            return '<h1>Invalid username or password</h1>'
    return render_template('login.html', form=loginForm)

@app.route('/user/<username>', methods=['GET','POST'])
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    cvForm = CVForm()
    cv = CV.query.filter_by(user_id=user.id).first()
    if cvForm.validate_on_submit():
        if cv:
            cv.fname = cvForm.fname.data
        else:
            new_cv = CV(fname=cvForm.fname.data, user_id=user.id)
            db.session.add(new_cv)
        db.session.commit()
    return render_template('user.html', username=current_user.username, form=cvForm, cv=cv)

@app.route('/my_CV')
@login_required
def my_CV():
    cv = CV.query.filter_by(user_id=current_user.id).first()
    return render_template('userCV.html', cv=cv)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    print('Logged out successfully')
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
