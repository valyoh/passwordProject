import configparser
from datetime import datetime

from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate  # Import Flask-Migrate
from flask_sqlalchemy import SQLAlchemy
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp, sr1
import threading
from ipaddress import ip_network
from concurrent.futures import ThreadPoolExecutor
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Load configuration from the db_config.ini file
config = configparser.ConfigParser()
config.read('db_config.ini')

# Extract database connection information
db_username = config['database']['username']
db_password = config['database']['password']
db_host = config['database']['host']
db_port = config['database'].get('port', '1433')  # Default to 1433 for SQL Server
db_name = config['database']['database']
db_driver = config['database']['driver']

# Construct the SQLAlchemy Database URI
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mssql+pyodbc://{db_username}:{db_password}@{db_host}:{db_port}/{db_name}?driver={db_driver}"
)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)


# Models
# Association table for many-to-many relationship between User and Vault
user_vaults = db.Table('user_vaults',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('vault_id', db.Integer, db.ForeignKey('vault.id'), primary_key=True)
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')
    # Many-to-many relationship with Vault
    vaults = db.relationship('Vault', secondary=user_vaults, backref='users')

class Vault(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False, unique=True)  # Add unique=True
    # Relationship to User is defined via the user_vaults association table

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vault_id = db.Column(db.Integer, db.ForeignKey('vault.id'))  # Link to the Vault
    website = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(150), nullable=False)  # Add username field
    password = db.Column(db.String(150), nullable=False)
    is_compromised = db.Column(db.Boolean, nullable=False, default=False)  # Add is_compromised field
    expiry_date = db.Column(db.Date, nullable=True)  # Add expiry_date field

    vault = db.relationship('Vault', backref='passwords')  # Relationship to Vault



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/network_scan', methods=['GET'])
@login_required
def scan_network_route():
    devices = []
    network_range = request.args.get('network_range')  # Get network range from the request

    # Only perform scan if network range is provided
    if network_range:
        devices = scan_network(network_range)  # Use the new Scapy scan function

    return render_template('network_scan.html', devices=devices, network_range=network_range)


@app.route('/')
def root():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))

@app.route('/create_vault', methods=['GET', 'POST'])
@login_required
def create_vault():
    if request.method == 'POST':
        vault_name = request.form['vault_name']

        # Check if a vault with the same name already exists
        existing_vault = Vault.query.filter_by(name=vault_name).first()
        if existing_vault:
            flash('Vault name already exists. Please choose a different name.')
            return redirect(url_for('create_vault'))

        new_vault = Vault(name=vault_name)

        # Add the new vault to the database
        db.session.add(new_vault)
        db.session.commit()

        # Assign the vault to the current user
        current_user.vaults.append(new_vault)
        db.session.commit()

        flash('Vault created successfully!')
        return redirect(url_for('vaults'))

    return render_template('create_vault.html')



@app.route('/vaults')
@login_required
def vaults():
    # Get the list of vaults assigned to the current user
    user_vaults = current_user.vaults
    return render_template('vaults.html', vaults=user_vaults)


@app.route('/vault/<int:vault_id>', methods=['GET', 'POST'])
@login_required
def vault(vault_id):
    # Check if the current user has access to the specified vault
    vault = Vault.query.filter(Vault.id == vault_id, Vault.users.contains(current_user)).first_or_404()

    # Get the passwords for this vault
    passwords = Password.query.filter_by(vault_id=vault.id).all()

    if request.method == 'POST':
        website = request.form['website']
        password = request.form['password']
        new_password = Password(vault_id=vault.id, website=website, password=password)
        db.session.add(new_password)
        db.session.commit()
        flash('Password added to vault!')
        return redirect(url_for('vault', vault_id=vault.id))

    return render_template('vault.html', vault=vault, passwords=passwords)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials.')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Get all the vaults for the current user
    #user_vaults = Vault.query.filter_by(user_id=current_user.id).all()
    user_vaults = current_user.vaults
    # Get passwords for each vault
    passwords = []
    for vault in user_vaults:
        passwords.extend(Password.query.filter_by(vault_id=vault.id).all())

    return render_template('dashboard.html', passwords=passwords)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    #flash('Logout successfully!')
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.role != 'admin':
        return "Unauthorized", 403  # Only allow admin users

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        new_user = User(username=username, password=generate_password_hash(password), role='user')
        db.session.add(new_user)
        db.session.commit()
        flash('New user added successfully!')
        return redirect(url_for('admin'))

    return render_template('admin.html')

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        return "Unauthorized", 403  # Only allow admin users
    users = User.query.all()  # Get all users with their associated vaults
    return render_template('admin_users.html', users=users)

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        return "Unauthorized", 403  # Only allow admin users

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.username = request.form['username']
        user.role = request.form['role']
        if request.form['password']:
            user.password = generate_password_hash(request.form['password'])
        db.session.commit()
        flash(f'User "{user.username}" updated successfully.')
        return redirect(url_for('admin_users'))

    return render_template('edit_user.html', user=user)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return "Unauthorized", 403  # Only allow admin users

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f'User "{user.username}" deleted successfully.')
    return redirect(url_for('admin_users'))

@app.route('/admin/assign_vault/<int:user_id>', methods=['GET', 'POST'])
@login_required
def assign_vault(user_id):
    if current_user.role != 'admin':
        return "Unauthorized", 403  # Only allow admin users

    user = User.query.get_or_404(user_id)
    available_vaults = Vault.query.all()  # Get all vaults

    if request.method == 'POST':
        selected_vault_id = request.form.get('vault_id')
        vault = Vault.query.get(selected_vault_id)

        if vault and vault not in user.vaults:
            user.vaults.append(vault)  # Assign the vault to the user
            db.session.commit()
            flash(f'Vault "{vault.name}" assigned to user "{user.username}".')
            return redirect(url_for('admin_users'))

    return render_template('assign_vault.html', user=user, vaults=available_vaults)

@app.route('/admin/unassign_vault/<int:user_id>/<int:vault_id>', methods=['POST'])
@login_required
def unassign_vault(user_id, vault_id):
    if current_user.role != 'admin':
        return "Unauthorized", 403  # Only allow admin users

    user = User.query.get_or_404(user_id)
    vault = Vault.query.get_or_404(vault_id)

    if vault in user.vaults:
        user.vaults.remove(vault)  # Unassign the vault from the user
        db.session.commit()
        flash(f'Vault "{vault.name}" unassigned from user "{user.username}".')

    return redirect(url_for('admin_users'))

@app.route('/add_password_page')
@login_required
def add_password_page():
    # Render the page to add a new password
    return render_template('add_password.html')

@app.route('/add_password', methods=['POST'])
@login_required
def add_password():
    website = request.form['website']
    username = request.form['username']
    password = request.form['password']
    is_compromised = 'is_compromised' in request.form  # Checkbox value, True if checked
    expiry_date_str = request.form.get('expiry_date')
    vault_id = request.form['vault_id']  # Get the selected vault ID

    # Convert the expiry_date from string to a date object, if provided
    expiry_date = None
    if expiry_date_str:
        try:
            expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid expiry date format. Please use YYYY-MM-DD.')
            return redirect(url_for('add_password_page'))

    # Create a new Password object
    new_password = Password(
        website=website,
        username=username,
        password=password,
        is_compromised=is_compromised,
        expiry_date=expiry_date,  # Use the converted date object
        vault_id=vault_id  # Use the selected vault ID
    )

    # Save the new password to the database
    db.session.add(new_password)
    db.session.commit()

    flash('Credential added successfully!')
    return redirect(url_for('dashboard'))


@app.route('/edit_password/<int:password_id>', methods=['GET', 'POST'])
@login_required
def edit_password_page(password_id):
    # Get the password entry to be edited
    password = Password.query.get_or_404(password_id)

    # Ensure the current user has access to the vault associated with this password
    if password.vault not in current_user.vaults:
        flash('Unauthorized access to the credential.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Update the password details
        password.website = request.form['website']
        password.username = request.form['username']
        password.password = request.form['password']
        password.is_compromised = 'is_compromised' in request.form
        expiry_date_str = request.form.get('expiry_date')

        # Convert expiry_date from string to date object
        password.expiry_date = None
        if expiry_date_str:
            try:
                password.expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date()
            except ValueError:
                flash('Invalid expiry date format. Please use YYYY-MM-DD.')
                return redirect(url_for('edit_password_page', password_id=password_id))

        db.session.commit()
        flash('Credential updated successfully!')
        return redirect(url_for('dashboard'))

    # Render the edit form
    return render_template('edit_password.html', password=password)


@app.route('/delete_password/<int:password_id>', methods=['POST'])
@login_required
def delete_password(password_id):
    # Get the password entry to be deleted
    password = Password.query.get_or_404(password_id)

    # Ensure the current user has access to the vault associated with this password
    if password.vault not in current_user.vaults:
        flash('Unauthorized access to the credential.')
        return redirect(url_for('dashboard'))

    # Delete the password entry
    db.session.delete(password)
    db.session.commit()
    flash('Credential deleted successfully.')
    return redirect(url_for('dashboard'))

# Define a lock for thread-safe print statements or list updates
lock = threading.Lock()

# Function to perform an ICMP ping scan on a single IP address
def icmp_ping(ip):
    ip_packet = IP(dst=str(ip)) / ICMP()
    response = sr1(ip_packet, timeout=0.5, verbose=0)
    if response:
        with lock:
            return {'ip': str(ip), 'hostname': "Unknown (ICMP)", 'state': "Online (ICMP)"}
    return None

def scan_network(network_range):
    devices = []

    # 1. Perform ARP scan to quickly identify devices in the local subnet
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    arp_result = srp(packet, timeout=1, verbose=0)[0]

    for sent, received in arp_result:
        devices.append({
            'ip': received.psrc,
            'hostname': received.hwsrc,
            'state': "Online (ARP)"
        })

    # 2. Perform multithreaded ICMP scan for remaining devices in the network range
    all_ips = [str(ip) for ip in ip_network(network_range).hosts()]
    scanned_ips = {device['ip'] for device in devices}  # Track ARP-scanned IPs to avoid duplicate ICMP scans

    # Filter out IPs that were already found with ARP
    icmp_targets = [ip for ip in all_ips if ip not in scanned_ips]

    # Use ThreadPoolExecutor to scan with ICMP in parallel
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(icmp_ping, icmp_targets))

    # Append results from ICMP scan that returned positive responses
    for result in results:
        if result:
            devices.append(result)

    return devices

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
        # Check if admin user exists
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', password=generate_password_hash('admin_password'), role='admin')
            db.session.add(admin_user)
            db.session.commit()
    app.run(debug=True)
