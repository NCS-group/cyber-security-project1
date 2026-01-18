# 🔐 Flask Login/Signup System with XAMPP MySQL

Complete authentication system with Python Flask and XAMPP MySQL database.

## 📋 Prerequisites

- Python 3.7 or higher
- XAMPP (for MySQL database)
- Web browser

## 🚀 Quick Setup Guide

### Step 1: Install XAMPP
1. Download XAMPP from https://www.apachefriends.org/
2. Install XAMPP on your computer
3. Open XAMPP Control Panel
4. Start **Apache** and **MySQL** services

### Step 2: Create Database
1. Open your browser and go to: http://localhost/phpmyadmin
2. Click on the **SQL** tab at the top
3. Open the `database_setup.sql` file from this project
4. Copy ALL the content and paste it into the SQL tab
5. Click **Go** button to execute
6. You should see "userdb" database created with a "users" table

### Step 3: Install Python Dependencies

**Option A: Using pip (recommended)**
```bash
pip install --user Flask flask-mysqldb mysqlclient
```

**Option B: Using requirements.txt**
```bash
pip install --user -r requirements.txt
```

**If you get permission errors:**
- Run Command Prompt as Administrator, OR
- Use the `--user` flag as shown above

### Step 4: Run the Application
```bash
python app.py
```

You should see:
```
==================================================
Flask App Starting...
Make sure XAMPP MySQL is running!
Database: userdb
Access the app at: http://127.0.0.1:5000
==================================================
```

### Step 5: Use the Application
1. Open browser: http://127.0.0.1:5000
2. You'll see the **Login** page
3. Click **"Create one"** to sign up
4. Fill in the signup form:
   - Username: your_name
   - Email: your_email@example.com
   - Password: minimum 6 characters
5. After signup, you'll be redirected to login
6. Login with your email and password
7. You'll see the **Dashboard** with your username

## 📁 Project Structure
```
project/
│
├── app.py                      # Main Flask application
├── database_setup.sql          # Database creation script
├── requirements.txt            # Python dependencies
├── README.md                   # This file
│
└── templates/
    ├── login.html             # Login page
    ├── signup.html            # Signup page
    └── dashboard.html         # Dashboard page
```

## ⚙️ Configuration

Database settings in `app.py`:
```python
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''  # Empty for default XAMPP
app.config['MYSQL_DB'] = 'userdb'
```

## ✨ Features

✅ User Registration (Signup)
- Username, email, and password fields
- Email format validation
- Password minimum length (6 characters)
- Duplicate email prevention
- Data saved to XAMPP MySQL database

✅ User Login
- Email and password authentication
- Session management
- Error messages for invalid credentials

✅ Dashboard
- Personalized welcome message
- Protected route (login required)
- Logout functionality

✅ Security
- Session-based authentication
- Form validation
- SQL injection prevention (parameterized queries)

## 🔧 Troubleshooting

### ❌ MySQL Connection Error
**Problem:** `Can't connect to MySQL server`
**Solution:**
- Open XAMPP Control Panel
- Make sure MySQL is running (green highlight)
- Check if port 3306 is not blocked

### ❌ Database Not Found
**Problem:** `Unknown database 'userdb'`
**Solution:**
- Go to phpMyAdmin: http://localhost/phpmyadmin
- Run the `database_setup.sql` script again
- Verify "userdb" appears in the left sidebar

### ❌ Module Not Found: flask_mysqldb
**Problem:** `ModuleNotFoundError: No module named 'flask_mysqldb'`
**Solution:**
```bash
pip install --user Flask flask-mysqldb mysqlclient
```

### ❌ mysqlclient Installation Error (Windows)
**Problem:** Error installing mysqlclient
**Solution:**
1. Download wheel file from: https://www.lfd.uci.edu/~gohlke/pythonlibs/#mysqlclient
2. Choose the correct version for your Python (e.g., cp310 for Python 3.10)
3. Install: `pip install mysqlclient‑1.4.6‑cp310‑cp310‑win_amd64.whl`

### ❌ Port 5000 Already in Use
**Problem:** `Address already in use`
**Solution:** Change port in app.py:
```python
app.run(debug=True, host='127.0.0.1', port=5001)
```

## 📝 Test Account

A test account is created automatically:
- **Email:** test@example.com
- **Password:** test123

## 🛡️ Security Notes

⚠️ **Important:** This is a basic authentication system for learning purposes.

For production use, you should:
- Hash passwords (use bcrypt or werkzeug.security)
- Use HTTPS
- Add CSRF protection
- Implement rate limiting
- Add email verification
- Use environment variables for secrets

## 📞 Support

If you encounter issues:
1. Make sure XAMPP MySQL is running
2. Check database exists in phpMyAdmin
3. Verify Python packages are installed
4. Check console for error messages

## 📄 License

Free to use for learning and personal projects.
