from flask import Flask, render_template, redirect, request, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired
from flask_bootstrap import Bootstrap5
from sqlalchemy.orm import relationship
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
import os
from dotenv import load_dotenv


load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
Bootstrap5(app)
login_manager = LoginManager()
login_manager.init_app(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DB','sqlite:///user.db')
db = SQLAlchemy()
db.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    lists = db.relationship("List", back_populates="user")


class List(db.Model):
    __tablename__ = 'lists'
    id = db.Column(db.Integer, primary_key=True)
    lists = db.Column(db.String(255))
    completed = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship("User", back_populates="lists")


with app.app_context():
    db.create_all()


class Form(FlaskForm):
    name = StringField(label="Name", validators=[DataRequired()])
    email = StringField(label='Email', validators=[DataRequired()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    submit = SubmitField("Submit")


class Login(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    signin = SubmitField("Sign-in")
    register = SubmitField("Register")


class ToDoList(FlaskForm):
    add = SubmitField("Add")
    logout = SubmitField("Log out")


class Edit(FlaskForm):
    edit_txt = StringField(label="Edit", validators=[DataRequired()])
    edit = SubmitField("Edit")


@app.route("/", methods=["POST", "GET"])
def home():
    form = Login()
    if form.register.data:
        return redirect(url_for('register'))
    if form.validate_on_submit():
        if form.signin.data:
            email = form.email.data
            password = form.password.data
            user = db.session.execute(db.select(User).where(User.email == email)).scalar()
            if user:
                if check_password_hash(user.password, password):
                    login_user(user)
                    return redirect(url_for('todolist'))
                else:
                    flash("Please Check Your Password")
                    return redirect(url_for('home'))
            else:
                flash("You Dont have account.Please Register")
                return redirect(url_for('register'))
    return render_template("login.html", form=form)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = Form()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        name = form.name.data
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if not user:
            new_user = User(
                email=email,
                password=generate_password_hash(password, method="pbkdf2:sha256", salt_length=4),
                name=name
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('todolist'))
        else:
            flash("You Already Have A Account")
            return redirect(url_for('home'))
    return render_template('register.html', form=form)


@app.route('/to-do-list', methods=["POST", "GET"])
@login_required
def todolist():
    form = ToDoList()
    user_todos = current_user.lists
    if form.validate_on_submit() and request.method == "POST":
        if form.add.data:
            list_data = request.form.get("add")
            print(list_data)
            new_list = List(lists=list_data, user=current_user, completed=0)
            db.session.add(new_list)
            db.session.commit()
            return redirect(url_for('todolist'))
        if form.logout.data:
            return redirect(url_for('logout'))
    return render_template('to-do-list.html', form=form, lists=user_todos)


@app.route('/completed/<int:id>', methods=["POST", "GET"])
@login_required
def completed(id):
    result = db.session.execute(db.select(List).where(List.id == id)).scalar()
    result.completed = 1
    db.session.commit()
    return redirect(url_for('todolist'))


@app.route('/delete/<int:id>', methods=["POST", "GET"])
@login_required
def delete(id):
    todo_to_delete = List.query.get(id)
    if todo_to_delete and todo_to_delete.user == current_user:
        db.session.delete(todo_to_delete)
        db.session.commit()
    return redirect(url_for('todolist'))


@app.route('/log-out')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/edit/<int:id>', methods=["POST", "GET"])
@login_required
def edit(id):
    form = Edit()
    if form.validate_on_submit():
        edit_txt = form.edit_txt.data
        print(edit_txt)
        edit_item = db.session.execute(db.select(List).where(List.id == id)).scalar()
        print(edit_item.lists)
        edit_item.lists = edit_txt
        db.session.commit()
        return redirect(url_for('todolist'))
    return render_template("edit.html", form=form)


if __name__ == '__main__':
    app.run(debug=True)
