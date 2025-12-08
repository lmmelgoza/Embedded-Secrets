# Embedded-Secrets
CSCI 490 Capstone Project
🖼️ Image Metadata & Steganography Web App

A React + FastAPI web application for exploring images, powered by Firebase for auth & storage. Upload a photo, inspect its metadata (EXIF/GPS), detect/extract hidden messages, and embed your own data into images.

Features

Metadata Extraction: Read EXIF (capture time, camera model), GPS, and PNG text chunks.

Steganography Detection: Extract hidden bytes/messages (e.g., LSB).

Data Embedding: Hide custom text/data in images.

User Accounts: Firebase Authentication (Email/Password, OAuth).

Storage: Upload original/processed images to Firebase Storage.

History: Save extraction/embedding results (via Firestore or your DB of choice).

Tech Stack

Frontend: React

Backend: Python FastAPI (image I/O, stego, crypto)

Firebase: Auth, Storage, (Firestore for history/logs)

Core Python libs: Pillow, NumPy, piexif (metadata), optional opencv-python, cryptography

Architecture (FastAPI × Firebase mix)

React handles file uploads and displays results.

______________________________________________________________________________________________________________________
Steps to Run Application on WSL
# replace <repo-url> with the repo remote URL
 - git clone <repo-url>
 - cd EmbeddedSecrets
# install dependencies and run dev server
 - npm install
 - npm run dev
 - Press "o" then enter to start frontend in your browser
# install required python packages
 - cd backend
 - python3 -m venv venv
 - source venv/bin/activate
 - python -m pip install --upgrade pip
 - pip install fastapi uvicorn[standard] python-multipart pillow piexif
 - For further pip installations look at backend/requirements.txt
# run backend on port 8000 (separate terminal)
- uvicorn app:app --reload --host 0.0.0.0 --port 8000

