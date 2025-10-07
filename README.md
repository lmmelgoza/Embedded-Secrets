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
