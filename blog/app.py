from flask import Flask, render_template, request, redirect, url_for, session, logging, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_migrate import Migrate
from flask_login import LoginManager, login_required, UserMixin, login_user, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/cordellcharles/documents/blog/blog.db'

app.secret_key = "Secret"

db = SQLAlchemy(app)

migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.login_view = '/'
login_manager.init_app(app)


class Blogpost(db.Model):
	id = db.Column(db.Integer, primary_key = True)
	title = db.Column(db.String(50))
	subtitle = db.Column(db.String(50))
	author = db.Column(db.String(20))
	date_posted = db.Column(db.DateTime)
	content = db.Column(db.Text)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)  

    def __init__(self, username, password_hash):
        self.username = username
        self.password_hash = password_hash

    def set_password(self, password):
        """Create hashed password."""
        self.password_hash = generate_password_hash(password, method= 'sha256')

    def check_password(self, password):
        """Check hashed password."""
        return check_password_hash(self.password_hash, password)
 
    def __repr__(self):
        return '< User {} >'.format(self.username)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/welcome')
@login_required
def welcome():

	return render_template('welcome.html', username= current_user.username)



@app.route('/home')
@login_required
def home():

	posts = Blogpost.query.order_by(Blogpost.date_posted.desc()).all()    # This will represent all posts in the database
	# return redirect(url_for('login', post= posts))
	return render_template('home.html', posts= posts, username= current_user.username)

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    else:
        return render_template('login.html')

# route for handling the login page logic
@app.route('/login', methods =['POST'])
def login():
    error = None

    #Bypass Login screen if user is logged in
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    else: 
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            print(username)

            user = User.query.filter_by(username= username).first()
            if user:
                print(user)
                if user.check_password(password):
                    login_user(user)
                    user.authenticated = True
                    return redirect(url_for('welcome'))
                else:
                    print('made it here')
                    flash('Invalid Username and/or Password! please try again')
                    return redirect(url_for('index'))

            else:
                print('at this point')
                error = 'Invalid Username and/or Password! please try again'
                flash(error)
                print('at this point(2)')
                return redirect(url_for('index'))


@app.route('/registration')
def registration():
    return render_template('user_registration.html')


@app.route('/user_registration', methods=['POST','GET'])
def user_registration():
    # form = User(request.form)
    username = request.form.get('username')
    password = request.form.get('password')
    password_2 = request.form.get('confirm password')
    

    print(username)
    print(password)
    print(password_2)

    if request.method == 'POST':
        existing_user = User.query.filter_by(username=username).first()
        if existing_user == None:
            print('success')
            if password != password:
                print(flash('ERROR! Password do not match! Please try again.','error'))
                db.session.rollback()
                return redirect(url_for('registration'))
            else:
                new_user = User(username= username, password_hash= generate_password_hash(password, method= 'sha256'))
                print(new_user)
                new_user.authenticated = True
                db.session.add(new_user)
                db.session.commit()
                return redirect('/')
        else:
            print('failed')
            print(flash('ERROR! This user ({}) already exists. Please choose another name!'.format(username), 'error'))
            db.session.rollback()
            return redirect(url_for('registration'))



@app.route('/logout')
@login_required
def logout():
    # Logs out user
    logout_user()
    return redirect(url_for('index'))

@app.route('/about')
@login_required
def about():
	return render_template('about.html')

@app.route('/post')
def post(post_id):

	post = Blogpost.query.filter_by(id= post_id).one()
	return render_template('post.html', post= post)


@app.route('/User/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = [
        {'author': user, 'body': 'Test post #1'},
        {'author': user, 'body': 'Test post #2'}
    ]
    return render_template('user.html', user=user, posts=posts)


@app.route('/add')
@login_required
def add():
	return render_template('add.html')

@app.route('/addpost', methods= ['POST'])
def addpost():
 
	title = request.form['title']
	subtitle = request.form['subtitle']
	author = request.form['author']
	content = request.form['content']

	post = Blogpost(title= title, subtitle= subtitle, author= author, content= content, date_posted= datetime.now())

	db.session.add(post)
	db.session.commit()

	return redirect(url_for('home'))


if __name__ == '__main__':
	app.run(debug=True)