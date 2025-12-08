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
import JPEG_Embed as jpeg_embed
import PNG_Embed as png_embed
from concurrent.futures import ThreadPoolExecutor
import io

#JPEG
import image_read as ir
from organize_meta import organize_meta


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


# New endpoint: embed / extract using CLI-style JPEG_Embed.py (capture and forward stdout)
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB

executor = ThreadPoolExecutor(max_workers=4)

@app.post("/api/secret")
async def secret_api(
    file: UploadFile = File(...),
    mode: str = Form(...),
    password: str = Form(...),
    message: str = Form("")
):
    data = await file.read()
    kind = sniff_format(data)

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

    in_fd, in_path = tempfile.mkstemp(suffix=suffix)
    os.close(in_fd)
    with open(in_path, "wb") as f:
        f.write(data)

    out_path = None
    try:
        mode_lower = mode.lower()

        if mode_lower == "embed":
            if not message:
                return JSONResponse(
                    status_code=400,
                    content={"status": "error", "detail": "Message is required for embedding."}
                )
            out_fd, out_path = tempfile.mkstemp(suffix=suffix)
            os.close(out_fd)

            # run embed in thread pool to avoid blocking
            await asyncio.get_event_loop().run_in_executor(
                executor,
                embed_func,
                in_path,
                out_path,
                message,
                password
            )

            if not os.path.exists(out_path):
                raise RuntimeError("Output file not created after embed.")

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
            extracted = await asyncio.get_event_loop().run_in_executor(
                executor,
                extract_func,
                in_path,
                password
            )
            return JSONResponse(
                content={
                    "status": "ok",
                    "mode": "extract",
                    "message": f"Recovered plaintext: {extracted}",
                }
            )
        else:
            return JSONResponse(
                status_code=400,
                content={"status": "error", "detail": "Mode must be 'embed' or 'extract'."}
            )

    except Exception as e:
        tb = traceback.format_exc()
        print("Exception in /api/secret:", tb)
        return JSONResponse(
            status_code=500,
            content={"status": "error", "detail": str(e)}
        )
    finally:
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
