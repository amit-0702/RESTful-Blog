from functools import wraps

from flask import abort, Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_gravatar import Gravatar
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from flask_ckeditor import CKEditor
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_login import login_user, UserMixin, logout_user, LoginManager, current_user
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_k(1"-38\83_09^&_#-kl]wt('
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


# CONFIGURE TABLE
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    # table_name.id  is given in foreignkey
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    comment_author = relationship("User", back_populates="comments")
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))

# db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    posts = db.session.query(BlogPost).all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("You've already signed up, Login Instead!")
            return redirect(url_for("login"))
        else:
            hash_and_salted_password = generate_password_hash(
                form.password.data,
                method='pbkdf2:sha256',
                salt_length=8
            )
            new_user = User(
                email=form.email.data,
                password=hash_and_salted_password,
                name=form.name.data
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_email = form.email.data
        user_password = form.password.data
        user = User.query.filter_by(email=user_email).first()
        if user:
            if check_password_hash(user.password, user_password):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Password Incorrect, Please try again.")
        else:
            flash("That Email does not exist, Please try again.")
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    post = BlogPost.query.get(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            user_comment = form.comment.data
            comment = Comment(
                text=user_comment,
                author_id=current_user.id,
                post_id=post_id,
            )
            db.session.add(comment)
            db.session.commit()
        else:
            flash("Please login to comment")
            return redirect(url_for("login"))
    gravatar = Gravatar(app,
                        size=100,
                        rating='g',
                        default='retro',
                        force_default=False,
                        force_lower=False,
                        use_ssl=False,
                        base_url=None)
    return render_template("post.html", post=post, form=form, gravatar=gravatar)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.id == 1:
            return f(*args, **kwargs)
        else:
            abort(403)
    return decorated_function


@app.route('/new-post', methods=['GET', 'POST'])
@admin_only
def add_new_post_form():
    form = CreatePostForm()
    if not form.validate_on_submit():
        return render_template("make-post.html", form=form, heading="Create New Post")
    else:
        blogpost = BlogPost()
        blogpost.title = form.title.data
        blogpost.subtitle = form.subtitle.data
        blogpost.img_url = form.img_url.data
        blogpost.body = form.body.data
        blogpost.date = datetime.datetime(datetime.datetime.now().year,
                                          datetime.datetime.now().month,
                                          datetime.datetime.now().day
                                          ).strftime("%B %d, %Y")
        db.session.add(blogpost)
        db.session.commit()
        return render_template("make-post.html", form=form, heading="Create New Post")


@app.route('/edit-post/<int:post_id>', methods=['GET', 'POST'])
@admin_only
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
    else:
        return render_template("make-post.html", form=edit_form, heading="Edit Post")


@app.route('/delete/<int:post_id>')
@admin_only
def delete_post(post_id):
    post = BlogPost.query.filter_by(id=post_id).first()
    if post:
        db.session.delete(post)
        db.session.commit()
    return redirect(url_for("get_all_posts"))


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000, debug=True)
