# Embedded-Secrets
CSCI 490 Capstone Project
🖼️ Image Metadata & Steganography Web App

A React + FastAPI web application for exploring images. Upload a photo, inspect its metadata (EXIF/GPS), detect/extract hidden messages, and embed your own data into images.

Features

Metadata Extraction: Scan JPEG and PNG files to retrieve embedded metadata such as GPS coordinates, creation/modification timestamps, and other header-level attributes

Steganographic Embedding: Embed custom metadata of payloads from stego images using password-protected decryption.

Secure Extraction: Extract embedded metadata or payloads from stego images using password-protected decryption.

RS Steganalysis: Perform RS (Regular-Singular) analysis to identify potential DCT-based embedding by flipping pixel or coefficient groups and generating a suspicion score

History: Save extraction/embedding results (via download JSON file).

Tech Stack

Frontend: React

Backend: Python FastAPI 

Core Python libs: Pillow, NumPy, piexif (metadata), opencv-python, cryptography

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

