import dns.resolver
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, Mapped, mapped_column
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from libravatar import libravatar_url
from functools import wraps
from sqlalchemy import ForeignKey
import os
from dotenv import load_dotenv


# load .env
load_dotenv()


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)


login_manager = LoginManager()
login_manager.init_app(app)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# avatar for comments in comment section
def get_avatar_url(email):
    try:
        return libravatar_url(email=email)
    except(dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return "https://www.gravatar.com/avatar/default"


# now add function to add the get_avatar_url function to jinja it's hard to remember
@app.context_processor
def utility_processor():
    return dict(get_avatar_url=get_avatar_url)


with app.app_context():
    class User(UserMixin, db.Model):
        __tablename__ = "users"
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(100), unique=True)
        password = db.Column(db.String(100))
        name = db.Column(db.String(100))
        # a list of all posts a particular person has written
        posts: Mapped[list["BlogPost"]] = relationship("BlogPost", back_populates="author")
        comments: Mapped[list["Comments"]] = relationship("Comments", back_populates="author")
    db.create_all()


with app.app_context():
    class BlogPost(db.Model):
        __tablename__ = "blog_posts"
        id = db.Column(db.Integer, primary_key=True)
        title = db.Column(db.String(250), unique=True, nullable=False)
        subtitle = db.Column(db.String(250), nullable=False)
        date = db.Column(db.String(250), nullable=False)
        body = db.Column(db.Text, nullable=False)
        img_url = db.Column(db.String(250), nullable=False)
        # relationship with User
        author: Mapped["User"] = relationship("User", back_populates="posts")
        # a foreign key which links according to the user id of the user
        author_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
        comments: Mapped[list["Comments"]] = relationship("Comments", back_populates="parent_post")
    db.create_all()

with app.app_context():
    class Comments(db.Model):
        __tablename__ = "comments"
        id = db.Column(db.Integer, primary_key=True)
        text = db.Column(db.String(250), nullable=False)
        author: Mapped["User"] = relationship("User", back_populates="comments")
        author_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
        parent_post: Mapped["BlogPost"] = relationship("BlogPost", back_populates="comments")
        post_id: Mapped[int] = mapped_column(ForeignKey("blog_posts.id"))
    db.create_all()


def admin_only(f):
    @wraps(f)  # MVP line helps preserve data of function
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hash_password = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256', salt_length=8)
        new_user = User(
            email=form.email.data,
            name=request.form.get('name'),
            password=hash_password
        )
        user = User.query.filter_by(email=new_user.email).first()
        if user:
            flash("Email already exists")
            return redirect(url_for('login'))
        else:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("This email does not exist")
        elif not check_password_hash(user.password, password):
            flash("Password incorrect")
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    global logged_in
    logged_in = False
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    form = CommentForm()
    comments = Comments.query.all()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Login or register to comment")
            return redirect(url_for("login"))
        new_comment = Comments(
            text=form.comment.data,
            author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated,
                           form=form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=['POST', 'GET'])
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['POST', 'GET'])
@admin_only
@login_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
@login_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route("/delete_comment/<int:id>")
@admin_only
@login_required
def delete_comment(id):
    data = Comments.query.get(id)
    post_id = data.parent_post.id
    db.session.delete(data)
    db.session.commit()
    return redirect(url_for("show_post", post_id=post_id))


if __name__ == "__main__":
    app.run(debug=True)
