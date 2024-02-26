from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, g
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('site.db')
        g.db.row_factory = sqlite3.Row
    return g.db

# Default route with navbar
@app.route('/')
def home():
    return render_template('home.html')

# Create the database table for patient entries
conn = sqlite3.connect('site.db')
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS patient_entries (
        id INTEGER PRIMARY KEY,
        patient_id INTEGER,
        username TEXT,
        sickness_info TEXT NOT NULL,
        time TEXT,
        date TEXT,
        FOREIGN KEY(patient_id) REFERENCES users(id)
    )
''')
conn.commit()
conn.close()

# Database initialization for users
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            user_type TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_type = request.form['user_type']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        # Check if the username already exists
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            flash('Username already exists. Please choose a different one.', 'error')
            conn.close()
            return redirect(url_for('signup'))

        # Use the default hashing method
        hashed_password = generate_password_hash(password)

        # Insert the new user into the database
        cursor.execute('INSERT INTO users (username, password, user_type) VALUES (?, ?, ?)',
                       (username, hashed_password, user_type))
        conn.commit()
        conn.close()

        flash('Account created successfully. Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


# Submit Sickness Info route for patients
@app.route('/submit_sickness_info', methods=['POST'])
def submit_sickness_info():
    if 'user_type' in session and session['user_type'] == 'patient':
        sickness_info = request.form['sickness_info']


        # Store the sickness information in the database for the patient
        # patient_id = session.get('user_id')

        
        conn = get_db()
        cursor = conn.cursor()

            # Get the current time and date
        current_time = datetime.now().strftime("%H:%M:%S")
        current_date = datetime.now().strftime("%Y-%m-%d")

            # Remove the username parameter and allow multiple entries for the same patient
        cursor.execute('INSERT INTO patient_entries (username, sickness_info, time, date) VALUES (?, ?, ?, ?)',
                        (session['username'], sickness_info, current_time, current_date))
        conn.commit()
        conn.close()
        print("Uploaded Successfully")

        return jsonify({'message': 'Sickness information submitted successfully'})
       
    else:
        return jsonify({'error': 'Unauthorized access'})


# Update doctor's dashboard with sickness entries
@app.route('/get_sickness_entries', methods=['GET'])
def get_sickness_entries():
    conn = get_db()
    cursor = conn.cursor()

    # Fetch sickness information from patient_entries
    cursor.execute('SELECT username, sickness_info, time, date FROM patient_entries')
    sickness_entries = cursor.fetchall()

    conn.close()

    return render_template('dashboard_doctor_entries.html', sickness_entries=sickness_entries)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        # Check if the username exists
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(user[2], password):
            flash('Login successful!', 'success')
            session['user_type'] = user[3]
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('dashboard', user_type=user[3]))
        else:
            flash('Login failed. Check your username and password.', 'error')

    return render_template('login.html')
    

# Logout route
@app.route('/logout')
def logout():
    session.pop('user_type', None)
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

# Dashboard route (protected route, user must be logged in)
@app.route('/dashboard/<user_type>', methods=['GET', 'POST'])
def dashboard(user_type):
    if 'user_type' not in session or session['user_type'] != user_type:
        flash('Please log in to access the dashboard.', 'error')
        return redirect(url_for('login'))

    if user_type == 'patient':
        if request.method == 'POST':
            sickness_info = request.form['sickness_info']
            flash(f'Sickness information submitted: {sickness_info}', 'success')
        return render_template('dashboard_patient.html', user_type=user_type)
    elif user_type == 'doctor':
        return render_template('dashboard_doctor.html', user_type=user_type)




if __name__ == '__main__':
    app.run(debug=True,port=5001)
