from flask import Flask, render_template, session, request, redirect, url_for, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.secret_key = 'somethingsupersecret'

#Database 
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    username = session.get('username')
    
    if not session.get ('logged_in'):
        return redirect(url_for('login'))
    
    return render_template('index.html')

#LOGIN PAGE
@app.route('/login', methods = ['GET', 'POST'])
def login():
    #If the user just visits /login (without submitting a form yet), Flask responds with the login HTML page
    if request.method == 'GET':
        return render_template('login.html')
    
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[0], password):
            session["logged_in"] = True
            session["username"] = username
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid username or password", "error")
            return redirect(url_for("login"))

    return render_template('login.html')

#SIGN UP PAGE
@app.route('/signup', methods = ['GET', 'POST'])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("Please fill out all fields", "error")
            return redirect(url_for("signup"))

        hashed_password = generate_password_hash(password)

        try:
            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            conn.close()

            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Username already exists.", "error")
            return redirect(url_for("signup"))

    # For GET requests → show the signup page
    return render_template('signup.html')


#HOME PAGE
@app.route('/home')
def home():
    if "logged_in" in session:
        return f"Welcome, {session['username']}!"
    else:
        return redirect(url_for("login"))
    
#LOGOUT ROUTE
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))
    
if __name__ == '__main__':
    app.run(debug=True)
    

