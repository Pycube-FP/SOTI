# Pycube Admin Dashboard

A modern Flask-based admin dashboard with authentication.

## Features

- Secure login system
- Modern, responsive UI using Tailwind CSS
- Dashboard with statistics and activity monitoring
- Protected routes requiring authentication

## Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

4. Create an admin user:
```bash
flask shell
>>> from app.models import User
>>> user = User(email='admin@pycube.com')
>>> user.set_password('admin@pycube.com')
>>> db.session.add(user)
>>> db.session.commit()
```

## Running the Application

1. Start the development server:
```bash
python run.py
```

2. Open your browser and navigate to `http://localhost:5000`

3. Login with:
   - Email: admin@pycube.com
   - Password: admin@pycube.com

## Project Structure

```
app/
├── __init__.py
├── models.py
├── auth/
│   ├── __init__.py
│   ├── forms.py
│   └── routes.py
├── main/
│   ├── __init__.py
│   └── routes.py
└── templates/
    ├── base.html
    ├── auth/
    │   └── login.html
    └── main/
        └── dashboard.html
``` 