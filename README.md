# NagarSetu Python Mini Project

A simple Flask-based civic issue management system inspired by the original NagarSetu project.

## Project Goal

This version keeps the same core logic as the original app while making it easier to explain, run, and dockerize for a college mini-project.

## Features Retained

- Citizen registration and login
- Admin and officer accounts are created only by an authenticated admin
- Citizen complaint creation with category, description, location, and priority
- Complaint photos: attach up to five JPG, PNG, GIF, or WEBP images
- Admin verification workflow
- Admin complaint assignment to officers
- Officer dashboard to start work and resolve complaints
- Complaint timeline and status updates
- Notifications for users
- Feedback after resolution
- Citizen or admin complaint closure with a required closing comment
- Active and closed complaints shown in separate dashboard sections
- SQLite database for simple storage

## Architecture

```text
Browser
  │
  ▼
Flask Web App
  │
  ├── Auth Module
  ├── Citizen Module
  ├── Admin Module
  ├── Officer Module
  │
  ▼
SQLite Database
```

## Default Login Accounts

- Admin: admin@nagarsetu.com / admin123
- Officer: officer@nagarsetu.com / officer123

## Run Locally

```bash
cd python_app
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open: http://localhost:5000

## Run with Docker

```bash
cd python_app
docker build -t nagarsetu-flask .
docker run -p 5000:5000 nagarsetu-flask
```

Or use Docker Compose:

```bash
docker compose up --build
```

## Main Files

- `app.py` – application logic and routes
- `templates/` – HTML pages for citizen, admin, and officer views
- `nagarsetu.db` – SQLite database created automatically

## Project Flow

```text
Citizen reports complaint
  ↓
Admin verifies complaint
  ↓
Admin assigns officer
  ↓
Officer starts work, adds a resolution comment, and resolves issue
  ↓
Citizen or admin adds a required closing comment and closes complaint
```

Public registration creates citizen accounts only. After signing in, an admin can use **Create Staff Account** to create additional admin or officer accounts.

## Why this version is better for college use

- Simple Python stack
- SQLite database instead of MongoDB
- Easy to explain in class
- Docker-friendly
- No complex frontend framework required
- Clear role-based architecture
