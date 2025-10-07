# app.py
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

import image_read as ir
from organize_meta import organize_meta

app = FastAPI()

# Allow your Vite dev server to call the API during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Vite default
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/analyze")
async def analyze_image(file: UploadFile = File(...)):
    # Optional: basic MIME/extension check
    if file.content_type not in ("image/jpeg", "image/jpg"):
        return {"error": "Please upload a JPEG (.jpg/.jpeg)"}

    data = await file.read()                  # <-- BYTES from the frontend
    meta = ir.read_image_from_bytes(data)     # <-- reuse your existing function
    organized = organize_meta(meta)           # <-- tidy up fields for UI
    return organized

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
