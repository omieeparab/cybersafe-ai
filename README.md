# CyberSafe AI

A Flask application for cybersecurity awareness and suspicious URL checks.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>.

## Deploy on Render

1. Create a GitHub repository with the contents of this folder at the repository root.
2. In Render, choose **New + → Blueprint** and connect that GitHub repository.
3. Render reads `render.yaml`, installs the dependencies, generates `SECRET_KEY`, and deploys the web service.
4. Copy the `https://…onrender.com` URL from the Render dashboard into the project presentation.

The local `users.json` is intentionally excluded from Git because it contains account credentials. A fresh deployment starts with no users; create an account on the deployed site. The free Render service may take a short time to wake after inactivity, and its local filesystem is temporary, so account data should not be treated as permanent.
