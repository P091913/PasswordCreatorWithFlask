from flask import Flask, render_template, request, redirect, url_for, flash, session
from cryptography.fernet import Fernet
import hashlib
import base64
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

Base = declarative_base()


class PasswordEntry(Base):
    __tablename__ = 'passwords'
    id = Column(Integer, primary_key=True)
    service = Column(String, unique=True, nullable=False)
    encrypted_password = Column(String, nullable=False)


engine = create_engine('sqlite:///passwords.db')
Base.metadata.create_all(engine)

Session = sessionmaker(bind=engine)
db_session = Session()

REAL_MASTER_PASSWORD = "pass"


def get_master_key(master_password):
    key = hashlib.sha256(master_password.encode()).digest()
    return base64.urlsafe_b64encode(key)


def is_logged_in():
    return 'master_key' in session


def get_fernet():
    return Fernet(session['master_key'])

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        entered_password = request.form['master_password']
        if entered_password == REAL_MASTER_PASSWORD:
            session['master_key'] = get_master_key(entered_password).decode()
            flash('Login successful.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Incorrect master password.', 'danger')

    return render_template('login.html')


@app.route('/home')
def index():
    if not is_logged_in():
        return redirect(url_for('login'))

    entries = db_session.query(PasswordEntry).all()
    return render_template('index.html', entries=entries)

@app.route('/add', methods=['POST'])
def add():
    if not is_logged_in():
        return redirect(url_for('login'))

    service = request.form['service']
    password = request.form['password']
    fernet = get_fernet()

    encrypted_password = fernet.encrypt(password.encode()).decode()

    existing_entry = db_session.query(PasswordEntry).filter_by(service=service).first()
    if existing_entry:
        flash('Service already exists. Use update instead.', 'warning')
    else:
        new_entry = PasswordEntry(service=service, encrypted_password=encrypted_password)
        db_session.add(new_entry)
        db_session.commit()
        flash('Password added successfully!', 'success')

    return redirect(url_for('index'))


@app.route('/view/<int:entry_id>')
def view_password(entry_id):
    if not is_logged_in():
        return redirect(url_for('login'))

    entry = db_session.query(PasswordEntry).filter_by(id=entry_id).first()
    fernet = get_fernet()

    if entry:
        try:
            decrypted_password = fernet.decrypt(entry.encrypted_password.encode()).decode()
            flash(f'Password for {entry.service}: {decrypted_password}', 'info')
        except:
            flash('Failed to decrypt password. Wrong master password?', 'danger')
    else:
        flash('Service not found.', 'danger')

    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.pop('master_key', None)
    flash('Logged out.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
