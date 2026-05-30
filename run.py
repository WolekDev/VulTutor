"""
VulTutor development entry point.

Run:
    python run.py

Then seed the database (first time only):
    python seed.py
"""

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
