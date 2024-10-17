# Flask Password Vault Management System

A Flask-based web application for managing user accounts, password vaults, and secure password storage. It includes user authentication, role-based access control (admin and regular users), and vault management functionality.

## Features

- User authentication (login and logout)
- Role-based access (admin and regular users)
- Admin functionalities:
  - Manage users (add, edit, delete)
  - Assign and unassign vaults to users
- User functionalities:
  - Create and manage personal vaults
  - Store passwords securely in vaults
- Password hashing for secure storage

## Prerequisites

Make sure you have the following installed on your system:

- Python 3.7+
- `pip` (Python package installer)
- `virtualenv` (optional, but recommended for creating a virtual environment)

## Setting Up the Project

Follow these steps to set up the project locally:

### 1. Clone the Repository

```bash
git clone https://github.com/your_username/your_repository_name.git
cd your_repository_name
```

### 2. Set Up a Virtual Environment (Recommended)
Create a virtual environment to isolate the project dependencies.

# For Windows
```bash
python -m venv venv
```
# For macOS/Linux
```bash
python3 -m venv venv
```

Activate the virtual environment:
# For Windows
```bash
venv\Scripts\activate
```
# For macOS/Linux
```bash
source venv/bin/activate
```

### 3. Install Dependencies
Install the required Python packages.

If you don't have a requirements.txt file, create it and add the following packages:

Flask
Flask-SQLAlchemy
Flask-Login
Flask-Migrate
Werkzeug

pip install -r requirements.txt

4. Configure the Database
Set up the database using Flask-Migrate.
# Initialize the migrations folder
flask db init

# Generate the initial migration script
flask db migrate -m "Initial migration"

# Apply the migration to create the database tables
flask db upgrade

5. Create an Admin User
Run the application once to set up the initial database and create an admin user:
python app.py
Visit http://localhost:5000 in your web browser. You can log in with the default admin credentials:

Username: admin
Password: admin_password
Make sure to change the admin password after the first login.

6. Running the Application
Start the Flask application.
python app.py

