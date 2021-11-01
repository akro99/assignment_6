from flask import Flask, render_template, url_for, request, redirect, session
from flask.helpers import flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import os,sys


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SECRET_KEY'] = 'mysecret'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_message="You need to login again."
login_manager.refresh_view='login'
login_manager.login_view='login'

class User(db.Model, UserMixin):
    __tablename__ ='user'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    email = db.Column(db.String(255))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))

    def __repr__(self):
        return '<User %r>' % self.id

class Role(db.Model):
    __tablename__ ='role'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  
    rolename = db.Column(db.String(50), unique=True)
    description = db.Column(db.String(50))

    def __repr__(self):
        return '<Role %r>' % self.id

class Task(db.Model):
    __tablename__ ='task'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    content = db.Column(db.String(200), nullable=False)
    date_completed = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    def __repr__(self):
        return '<Task %r>' % self.id

class Permission:
    ADDTASK = 0x01
    ADDDATE = 0x02

role_permission = {
    "admin": (Permission.ADDTASK | Permission.ADDDATE),
    "user": (Permission.ADDTASK)
}

def check_permission(user_id, requestedPermission):
    user = User.query.filter_by(id = user_id).first()
    role = Role.query.filter_by(id = user.role_id).first()
    permittedPermission = role_permission[role.rolename]
    if (permittedPermission & requestedPermission):
        return True
    return False

if not os.path.exists(sys.path[0] + './todo.db'):
    db.create_all()
    db.session.add(Role(rolename="admin", description="Admin User"))
    db.session.add(Role(rolename="user", description="Regular User"))
    db.session.commit()

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == "POST":
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password)
        new_user = User(
            username = username,
            email = email,
            password = hashed_password,
            role_id = Role.query.filter_by(rolename = "user").first().id)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Successfully Registered 💗")
            return redirect(url_for('login'))
        except Exception as e:
            print(e)
            flash("Exception occurred 😯")
            return 'Fail to add user.'
    else:
        return render_template('signup.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if user:
            if bcrypt.check_password_hash(user.password, request.form["password"]):
                login_user(user)
                return redirect(url_for("task"))
    
        flash("User does not exist, or invalid username or password 👾")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("See you 🌟")
    return redirect(url_for('login'))

@app.route("/")
def home():
    return render_template('home.html')

@app.route("/productnew")
def product():
    return render_template('productnew.html')

@app.route('/task', methods=['POST', 'GET'])
@login_required
def task():
    if request.method == 'POST':
        task_content = request.form['content']
        if (check_permission(session['_user_id'], Permission.ADDDATE)):
            task_date_completed = datetime.datetime.strptime(request.form['date_completed'], '%Y-%m-%d')
        else:
            task_date_completed = None
        new_task = Task(content=task_content, date_completed=task_date_completed, user_id=session['_user_id'])

        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect(url_for('task'))
        except Exception as e:
            return 'There was an issue adding your task.' + str(e)

    else:
        user_id = session['_user_id']
        tasks = Task.query.filter_by(user_id=user_id).all()
        return render_template('task.html', tasks=tasks, showDDL=check_permission(user_id, Permission.ADDDATE))

@app.route('/delete/<int:id>')
def delete(id):
    task_to_delete = Task.query.get_or_404(id)

    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect('/task')
    except:
        return 'There was a problem deleting that task'

import datetime

@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    task = Task.query.filter_by(id=id).first()

    if request.method == 'POST':
        task.content = request.form['content']
        if (check_permission(session['_user_id'], Permission.ADDDATE)):
            task.date_completed = datetime.datetime.strptime(request.form['date_completed'], '%Y-%m-%d')
        else:
            task.date_completed = None

        try:
            db.session.commit()
            return redirect('/task')
        except Exception as e:
            return 'There was an issue updating your task.' + str(e)

    else:
        user_id = session['_user_id']
        return render_template('update.html', task=task, showDDL=check_permission(user_id, Permission.ADDDATE))

if __name__ == "__main__":
    app.run('localhost', 9909)
