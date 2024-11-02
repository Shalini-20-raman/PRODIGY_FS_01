from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import Error
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def authenticate(username, password):
    # Sample authentication logic
    if username == 'admin' and password == 'password':
        return True
    return False


# Database connection
def create_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Meena@2096",
        database="sua"
    )

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Authenticate the user (e.g., check against the database)
        if authenticate(username, password):
            # Store user information in the session
            session['username'] = username
            return redirect(url_for('dashboard'))  # Redirect to the dashboard or another page

        # If authentication fails
        return "Login failed. Please try again."

        try:
            conn = create_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()

            if user and check_password_hash(user['password'], password):
                session['loggedin'] = True
                session['id'] = user['id']
                session['username'] = user['username']
                return redirect(url_for('dashboard'))
            else:
                flash("Incorrect username or password")

        except Error as e:
            print(f"Error: {e}")
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Basic form validation
        if not re.match(r'[A-Za-z0-9]+', username):
            flash("Username must contain only characters and numbers!")
        elif password != confirm_password:
            flash("Passwords do not match!")
        else:
            hashed_password = generate_password_hash(password)

            try:
                conn = create_db_connection()
                cursor = conn.cursor()
                cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
                conn.commit()
                flash("Registration successful!")
                return redirect(url_for('login'))

            except Error as e:
                print(f"Error: {e}")
                flash("Something went wrong!")
            finally:
                if conn.is_connected():
                    cursor.close()
                    conn.close()

    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'loggedin' in session:
        return f"Hello, {session['username']}! Welcome to your dashboard."
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
