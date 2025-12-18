# app.py
import asyncio
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, FileResponse
import uvicorn
import json
import tempfile
import os
import base64
import traceback
import subprocess
import sys

from concurrent.futures import ThreadPoolExecutor
import io

#JPEG
import image_read as ir
from organize_meta import organize_meta
import JPEG_Embed as jpeg_embed
import PNG_Embed as png_embed


#PNG
import png_read as pr
from organize_png_meta import organize_meta as organize_png_meta


app = FastAPI()

# Allow your Vite dev server to call the API during development
# Read allowed origins from env (comma-separated), default to localhost:5173 for dev
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PNG_SIG = b"\x89PNG\r\n\x1a\n"

# Determine the image format (PNG, JPEG or Unknown) from raw bytes
# Steps:
# 1. Check if the data starts with the PNG signature
# 2. If not PNG, check if the data starts with JPEG SOI marker
# 3. If neither, return 'UNKNOWN'
# Returns: "PNG", "JPEG", or "UNKNOWN" based on magic bytes
def sniff_format(data: bytes) -> str:
    # Step 1
    if data.startswith(PNG_SIG):
        return "PNG"
    # Step 2
    if data.startswith(b"\xff\xd8"):
        return "JPEG"
    # Step 3
    return "UNKNOWN"

# Analyze an uploaded image and return organized metadata
# Steps:
# 1. Read the uploaded file bytes
# 2. Detect the image format using sniff_format
# 3. For JPEG: decode and parse metadata with image_read + organize_meta
#    For PNG: decode and parse metadata with png_read + organize_png_meta
# 4. Return: JSON metadata structure or error description
@app.post("/analyze")
async def analyze_image(file: UploadFile = File(...)):
    # Step 1
    data = await file.read()
    # Step 2
    kind = sniff_format(data)

    if kind == "JPEG":
        # Step 3 for JPEG
        meta = ir.read_image_from_bytes(data)
        return organize_meta(meta)
    
    if kind == "PNG":
        # Step 3 for PNG
        meta = pr.read_image_from_bytes(data)
        return organize_png_meta(meta)

    # Step 4
    return {"error": "Please upload a JPEG (.jpg/.jpeg) or a PNG (.png) image."}


# New endpoint: embed / extract using CLI-style JPEG_Embed.py (capture and forward stdout)
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB

executor = ThreadPoolExecutor(max_workers=4)

# Embed or extract an encrypted secret message inside JPEG/PNG images
# Steps: 
# 1. Read the uploaded file and detect its format (JPEG/PNG)
# 2. Choose the correct embed/extract functions and file settings based on the format
# 3. Write the uploaded image bytes to a temporary input file
# 4. Normalize and inspect the requested mode ("embed" or "extract")
# 5. If mode is "embed":
#    5.1 Validate that a non-empty message is provided
#    5.2. Create a temporary output file path
#    5.3. Run the embed operation in a thread pool to avoid blocking
#    5.4. Ensure the stego output file exists.
# 6. If mode is "extract":
#    6.1. Run the extract operation in a thread pool
#    6.2. Return the recovered plaintext in a JSON response
# 7. If mode is invalid, return a 400 error response
# 8. On any exception, log the traceback and return a 500 error
# 9. Always clean up temporary files
@app.post("/api/secret")
async def secret_api(
    file: UploadFile = File(...),
    mode: str = Form(...),
    password: str = Form(...),
    message: str = Form("")
):
    # Step 1
    data = await file.read()
    kind = sniff_format(data)
    # Step 2
    if kind == "JPEG":
        embed_func = jpeg_embed.embed
        extract_func = jpeg_embed.extract
        suffix = ".jpg"
        mime = "image/jpeg"
    elif kind == "PNG":
        embed_func = png_embed.embed
        extract_func = png_embed.extract
        suffix = ".png"
        mime = "image/png"
    else:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "detail": "Only JPEG and PNG images are supported."}
        )
    # Step 3
    in_fd, in_path = tempfile.mkstemp(suffix=suffix)
    os.close(in_fd)
    with open(in_path, "wb") as f:
        f.write(data)

    out_path = None
    try:
        # Step 4
        mode_lower = mode.lower()

        if mode_lower == "embed":
            # Step 5.1
            if not message:
                return JSONResponse(
                    status_code=400,
                    content={"status": "error", "detail": "Message is required for embedding."}
                )
            # Step 5.2
            out_fd, out_path = tempfile.mkstemp(suffix=suffix)
            os.close(out_fd)

            # Step 5.3 run embed in thread pool to avoid blocking
            await asyncio.get_event_loop().run_in_executor(
                executor,
                embed_func,
                in_path,
                out_path,
                message,
                password
            )
            # Step 5.4
            if not os.path.exists(out_path):
                raise RuntimeError("Output file not created after embed.")
            # Step 5.5
            with open(out_path, "rb") as f:
                stego_bytes = f.read()
            stego_b64 = base64.b64encode(stego_bytes).decode("ascii")

            return JSONResponse(
                content={
                    "status": "ok",
                    "mode": "embed",
                    "input_path": file.filename,
                    "output_path": os.path.basename(out_path),
                    "bytes_embedded": len(message),
                    "stego_image_b64": stego_b64,
                    "mime_type": mime,
                }
            )

        elif mode_lower == "extract":
            # Step 6.1
            extracted = await asyncio.get_event_loop().run_in_executor(
                executor,
                extract_func,
                in_path,
                password
            )
            # Step 6.2
            return JSONResponse(
                content={
                    "status": "ok",
                    "mode": "extract",
                    "message": f"Recovered plaintext: {extracted}",
                }
            )
        else:
            # Step 7
            return JSONResponse(
                status_code=400,
                content={"status": "error", "detail": "Mode must be 'embed' or 'extract'."}
            )

    except Exception as e:
        # Step 8
        tb = traceback.format_exc()
        print("Exception in /api/secret:", tb)
        return JSONResponse(
            status_code=500,
            content={"status": "error", "detail": str(e)}
        )
    finally:
        # Step 9
        try:
            if os.path.exists(in_path):
                os.remove(in_path)
        except Exception:
            pass
        try:
            if out_path and os.path.exists(out_path):
                os.remove(out_path)
        except Exception:
            pass


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
