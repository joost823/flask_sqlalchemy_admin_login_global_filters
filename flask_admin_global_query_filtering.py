from flask import Flask, redirect, url_for, request
import flask_admin
from flask_admin import Admin, expose, helpers
from flask_admin.contrib.sqla import ModelView
from flask_sqlalchemy import SQLAlchemy, BaseQuery
from flask_login import login_user, logout_user, current_user, LoginManager, \
    UserMixin
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from sqlalchemy import distinct, func


def check_mapper(query, ignore_filter):
    """check a query for certain classes, and apply filters"""

    # otherwise flask-login gets stuck in recursive loop
    if ignore_filter:
        return query

    # find model clas connected to query
    some_mapping_unit = query._mapper_zero()
    if not some_mapping_unit:
        some_mapping_unit = (query._select_from_entity)
    if not some_mapping_unit:
        raise Exception('Im not sure when this might happen')

    # filter tables if user is logged in
    if current_user and current_user.is_authenticated:
        queried_class = some_mapping_unit.class_
        if queried_class == User:
            return query.enable_assertions(False).filter(User.id == current_user.id)
        elif queried_class == Book:
            return query.enable_assertions(False).filter(Book.user_id == current_user.id)
        elif queried_class == Page:
            return query.enable_assertions(False).join(Book).filter(Book.user_id == current_user.id)
        elif queried_class == Word:
            return query.enable_assertions(False).join(Page, Word.page).join(Book, Page.book).filter(Book.user_id == current_user.id)
        else:
            return query

    # if user is not logged in, show all data
    else:
        return query


class LimitingQuery(BaseQuery):
    """adjusted query where ALL queries from this app, either from
    db.session.query, or MyModel.query go through

    flask-login queries the database to get the data of the current logged
    in user, but to query the database, we need to know whether to user is
    logged in to filter certain results (infinite loop). Therefore, we need a
    special argument at the get function so we know when it is flask-login
    making the query, so we don't apply filters on that query"""
    ignore_filter = False

    def get(self, ident, ignore_filter=False):
        query = check_mapper(self, ignore_filter)
        return super(LimitingQuery, query).get(ident)

    def __iter__(self):
        return BaseQuery.__iter__(self.private())

    def from_self(self, *ent):
        return BaseQuery.from_self(self.private(), *ent)

    def private(self):
        return check_mapper(self, self.ignore_filter)


app = Flask(__name__)
app.secret_key = 'arsarhardsahrastrpshntrdnstedtp5g6jljhbtarst'
db = SQLAlchemy(app, query_class=LimitingQuery)


@app.route('/')
@app.route('/index')
def index():
    return redirect('/admin')


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    books = db.relationship('Book')

    def __repr__(self):
        return '<User {}>'.format(self.email)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __str__(self):
        return self.email


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    pages = db.relationship('Page', backref='book')

    def __str__(self):
        return self.title


class Page(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.Integer)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'))
    words = db.relationship('Word', secondary='word_to_page_junction', lazy='subquery',
                            backref=db.backref('page', lazy=True))

    def __str__(self):
        return str(self.number)


class Word(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)

    def __str__(self):
        return self.name


class WordToPageJunction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    page_id = db.Column(db.Integer, db.ForeignKey('page.id'), nullable=False)
    word_id = db.Column(db.Integer, db.ForeignKey('word.id'), nullable=False)


db.create_all()
login = LoginManager(app)
login.login_view = 'login'


@login.user_loader
def load_user(id):
    # load the user, and turn filtering off
    return User.query.get(int(id), ignore_filter=True)


class MyAdminIndexView(flask_admin.AdminIndexView):
    @expose('/')
    def index(self):
        if not current_user.is_authenticated:
            return redirect(url_for('.login_view'))
        return super(MyAdminIndexView, self).index()

    @expose('/login/', methods=('GET', 'POST'))
    def login_view(self):
        form = LoginForm(request.form)
        if helpers.validate_form_on_submit(form):
            user = User.query.filter_by(email=form.email.data).first()
            if user and user.check_password(form.password.data):
                login_user(user)

        if current_user.is_authenticated:
            return redirect(url_for('.index'))
        link = '<p>Don\'t have an account? <a href="' + url_for('.register_view') + '">Click here to register.</a></p>'
        self._template_args['form'] = form
        self._template_args['link'] = link
        return super(MyAdminIndexView, self).index()

    @expose('/register/', methods=('GET', 'POST'))
    def register_view(self):
        form = RegistrationForm(request.form)
        if helpers.validate_form_on_submit(form):
            user = User()
            form.populate_obj(user)
            user.password = generate_password_hash(form.password.data)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('.index'))

        link = '<p>Already have an account? <a href="' + url_for('.login_view') + '">Click here to log in.</a></p>'
        self._template_args['form'] = form
        self._template_args['link'] = link
        return super(MyAdminIndexView, self).index()

    @expose('/logout/')
    def logout_view(self):
        logout_user()
        return redirect(url_for('.index'))


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')


class WordView(ModelView):
    def get_count_query(self):
        """we need a special count query, otherwise n rows matching in junction
        table are displayed instead of right answer"""
        return self.session.query(func.count(distinct(Word.id)))
    column_searchable_list = ['name']


class BookView(ModelView):
    column_searchable_list = ['title', 'user_id']

    def on_model_change(self, form, model, is_created):
        if is_created and current_user.is_authenticated:
            model.user_id = current_user.id
        return super(BookView, self).on_model_change(form, model, is_created)


admin = Admin(app, 'Example: Auth', index_view=MyAdminIndexView(), base_template='my_master.html')
admin.add_view(ModelView(User, db.session))
admin.add_view(BookView(Book, db.session))
admin.add_view(ModelView(Page, db.session))
admin.add_view(WordView(Word, db.session))


def add_db_samples():
    dummy_data = {
        'user1@email.com': {
            'harry potter': {
                1: ['yer', 'a', 'wizard', 'herry'],
                2: ['no', 'way', 'hagrid']
            },
            'egg cookbook': {
                5: ['a', 'recipe', 'for', 'scrambled', 'eggs'],
                6: ['no', 'really', 'yummy', 'eggs']
            }
        },
        'user2@email.com': {
            'da vinci code': {
                11: ['some', 'action'],
                12: ['some', 'romance']
            }
        }
    }

    for email in dummy_data:
        user = User(email=email)
        user.set_password('blabla')
        for title in dummy_data[email]:
            book = Book(title=title)
            for page_number in dummy_data[email][title]:
                page = Page(number=page_number)
                for word_name in dummy_data[email][title][page_number]:
                    word = Word.query.filter_by(name=word_name).first()
                    if not word:
                        word = Word(name=word_name)
                    page.words.append(word)
                    db.session.add(word)
                    db.session.commit()
                book.pages.append(page)
            user.books.append(book)
        db.session.add(user)
    db.session.commit()


add_db_samples()
