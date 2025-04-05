from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import sqlite3

# Initialize the Flask app
app = Flask(__name__)

# Configuration for the Flask app
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///medic.db'
app.config['SECRET_KEY'] = 'your_secret_key'

# Initialize the database
db = SQLAlchemy(app)

# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Hardcoded Admin Credentials
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = '1234'  # Example admin password

# Define User and Patient models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'user' or 'admin'
    is_active = db.Column(db.Boolean, default=True)

    patients = db.relationship('Patient', backref='user', lazy=True)

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    sex = db.Column(db.String(10), nullable=False)
    bmi = db.Column(db.Float, nullable=False)
    children = db.Column(db.Integer, nullable=False)
    charges = db.Column(db.Float, nullable=False)
    region = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Define the user loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Ensure the 'is_active' column exists in the user table
def ensure_is_active_column():
    with sqlite3.connect('medic.db') as conn:
        cursor = conn.cursor()
        # Check if the user table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user'")
        table_exists = cursor.fetchone()
        if table_exists:
            cursor.execute("PRAGMA table_info(user)")
            columns = [col[1] for col in cursor.fetchall()]
            if 'is_active' not in columns:
                cursor.execute("ALTER TABLE user ADD COLUMN is_active BOOLEAN DEFAULT 1")
                conn.commit()

# Route to home page
@app.route('/')
def home():
    return render_template('home.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            return render_template('register.html', error="Username already exists")

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check for admin login
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            user = User.query.filter_by(username=username).first()
            if not user:
                user = User(username=username, password=generate_password_hash(password))
                db.session.add(user)
                db.session.commit()
            login_user(user)
            return redirect(url_for('index'))

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))

        return render_template('login.html', error="Invalid username or password")

    return render_template('login.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Index route where users can see their data or the admin can see all data
@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        # Add new patient data
        name = request.form.get('name')
        age = request.form.get('age')
        sex = request.form.get('sex')
        bmi = request.form.get('bmi')
        children = request.form.get('children')
        charges = request.form.get('charges')
        region = request.form.get('region')

        # Validate mandatory fields
        if not name or not age or not sex or not bmi or not children or not charges or not region:
            flash('All fields are required', 'error')
        else:
            new_patient = Patient(
                name=name,
                age=int(age),
                sex=sex,
                bmi=float(bmi),
                children=int(children),
                charges=float(charges),
                region=region,
                user_id=current_user.id
            )
            db.session.add(new_patient)
            db.session.commit()
            flash('Patient added successfully!', 'success')

    if current_user.username == ADMIN_USERNAME:
        patients = Patient.query.all()  # Admin can see all patients
    else:
        patients = Patient.query.filter_by(user_id=current_user.id).all()  # Regular users can see only their own patients

    return render_template('index.html', patients=patients, is_admin=(current_user.username == ADMIN_USERNAME))

# Update route (GET and POST)
@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    patient = Patient.query.get_or_404(id)
    if current_user.username != ADMIN_USERNAME and patient.user_id != current_user.id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        patient.name = request.form['name']
        patient.age = request.form['age']
        patient.sex = request.form['sex']
        patient.bmi = request.form['bmi']
        patient.children = request.form['children']
        patient.charges = request.form['charges']
        patient.region = request.form['region']

        db.session.commit()
        flash('Patient updated successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('update.html', patient=patient)

# Delete route (POST)
@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete(id):
    try:
        # Fetch the patient record
        patient = Patient.query.get_or_404(id)

        if current_user.username != ADMIN_USERNAME and patient.user_id != current_user.id:
            flash('Unauthorized access', 'error')
            return redirect(url_for('index'))

        # Delete the patient record
        db.session.delete(patient)
        db.session.commit()

        flash('Patient deleted successfully!', 'success')
        return redirect(url_for('index'))

    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting patient: {str(e)}', 'error')
        return redirect(url_for('index'))

# Additional routes
@app.route('/queries')
def queries():
    return render_template('queries.html')

@app.route('/patients')
def patients():
    return render_template('patient.html')

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    if current_user.username == ADMIN_USERNAME:
        patient_list = Patient.query.all()  # Admin can see all patients
    else:
        patient_list = Patient.query.filter_by(user_id=current_user.id).all()  # Regular users can see only their own patients

    patients = [{
        'id': patient.id,
        'name': patient.name,
        'age': patient.age,
        'sex': patient.sex,
        'bmi': patient.bmi,
        'children': patient.children,
        'charges': patient.charges,
        'region': patient.region
    } for patient in patient_list]
    return render_template('dashboard.html', content=patients, is_admin=(current_user.username == ADMIN_USERNAME))


@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/help')
def help():
    return render_template('help.html')

# Search route
@app.route('/search', methods=['GET'])
@login_required
def search():
    query = request.args.get('query', '')
    if current_user.username == ADMIN_USERNAME:
        patients = Patient.query.filter(Patient.name.ilike(f"%{query}%")).all()
    else:
        patients = Patient.query.filter(
            Patient.user_id == current_user.id,
            Patient.name.ilike(f"%{query}%")
        ).all()

    return render_template('search.html', patients=patients, query=query)

# Main entry point
if __name__ == '__main__':
    with app.app_context():  # Ensure the application context is set
        db.create_all()  # Create the database tables if they don't exist
        ensure_is_active_column()  # Ensure the 'is_active' column is present

    app.run( debug=True)
