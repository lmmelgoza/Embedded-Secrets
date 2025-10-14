# app.py
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import json
#JPEG
import image_read as ir
from organize_meta import organize_meta
#PNG
import png_read as pr
from organize_png_meta import organize_meta as organize_png_meta

app = FastAPI()

# Allow your Vite dev server to call the API during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Vite default
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PNG_SIG = b"\x89PNG\r\n\x1a\n"

def sniff_format(data: bytes) -> str:
    if data.startswith(PNG_SIG):
        return "PNG"
    if data.startswith(b"\xff\xd8"):
        return "JPEG"
    return "UNKNOWN"

@app.post("/analyze")
async def analyze_image(file: UploadFile = File(...)):
    data = await file.read()
    kind = sniff_format(data)

    if kind == "JPEG":
        meta = ir.read_image_from_bytes(data)
        return organize_meta(meta)
    
    if kind == "PNG":
        meta = pr.read_image_from_bytes(data)
        return organize_png_meta(meta)

    return {"error": "Please upload a JPEG (.jpg/.jpeg) or a PNG (.png) image."}

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
