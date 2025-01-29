from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'secretkey'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Model użytkownika
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)


# Model ogłoszenia
class Ad(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(1000), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('ads', lazy=True))


# Formularz rejestracji
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField('Register')


# Formularz logowania
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField('Login')


# Formularz ogłoszenia
class AdForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired(), Length(min=1, max=200)])
    description = StringField('Description', validators=[InputRequired(), Length(min=1, max=1000)])
    submit = SubmitField('Add Ad')


# Strona główna
@app.route('/')
def index():
    ads = Ad.query.all()
    return render_template('index.html', ads=ads)


# Rejestracja użytkownika
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Rejestracja zakończona sukcesem!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Tests 
# Logowanie użytkownika
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.password == form.password.data:
            login_user(user)
            return redirect(url_for('index'))
        flash('Nieprawidłowy email lub hasło!', 'danger')
    return render_template('login.html', form=form)


# Dodawanie ogłoszenia
@app.route('/add_ad', methods=['GET', 'POST'])
@login_required
def add_ad():
    form = AdForm()
    if form.validate_on_submit():
        ad = Ad(title=form.title.data, description=form.description.data, user_id=current_user.id)
        db.session.add(ad)
        db.session.commit()
        flash('Ogłoszenie zostało dodane!', 'success')
        return redirect(url_for('index'))
    return render_template('add_ad.html', form=form)


# Usuwanie ogłoszenia
@app.route('/delete_ad/<int:ad_id>', methods=['POST'])
@login_required
def delete_ad(ad_id):
    ad = Ad.query.get_or_404(ad_id)

    # Sprawdzenie, czy użytkownik jest właścicielem ogłoszenia
    if ad.user_id != current_user.id:
        flash('Nie masz uprawnień do usunięcia tego ogłoszenia!', 'danger')
        return redirect(url_for('index'))

    db.session.delete(ad)
    db.session.commit()
    flash('Ogłoszenie zostało usunięte!', 'success')
    return redirect(url_for('index'))


# Wylogowywanie
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# Ładowanie użytkownika
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)