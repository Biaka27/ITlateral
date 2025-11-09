from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    address = db.Column(db.String(250), nullable=True)

with app.app_context():
    db.create_all()

# Home route
@app.route('/')
def home():
    return redirect(url_for('login'))

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        address = request.form['address']

        if not username or not password or not address:
            flash('All fields are required.', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(username=username, password=hashed_password, address=address)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except:
            flash('Username already exists. Try another one.', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['username'] = user.username
            session['address'] = user.address
            flash('Login successful!', 'success')
            return redirect(url_for('success'))
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

# Success page
@app.route('/success')
def success():
    if 'username' in session:
        return render_template('success.html', username=session['username'], address=session['address'])
    else:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

# Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('address', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Manage users
@app.route('/manage_users')
def manage_users():
    users = User.query.all()
    return render_template('manage_users.html', users=users)

# Delete user
@app.route('/delete_user/<int:id>', methods=['POST'])
def delete_user(id):
    user = User.query.get_or_404(id)
    try:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    except:
        flash('Error deleting user.', 'error')
    return redirect(url_for('manage_users'))

if __name__ == '__main__':
    app.run(debug=True)
