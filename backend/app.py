# app.py
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
import uvicorn
import json
import tempfile
import os
import base64
import traceback
import subprocess
import sys
#JPEG
import image_read as ir
from organize_meta import organize_meta
#import JPEG_Embed as jpeg_embed  # no longer calling functions directly

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


# New endpoint: embed / extract using CLI-style JPEG_Embed.py (capture and forward stdout)
@app.post("/api/secret")
async def secret_api(
    file: UploadFile = File(...),
    mode: str = Form(...),
    password: str = Form(...),
    message: str = Form("")  # optional for extract
):
    data = await file.read()
    kind = sniff_format(data)

    # allow JPEG or PNG, pick script and file suffix/mime accordingly
    if kind == "JPEG":
        script_name = "JPEG_Embed.py"
        in_suffix = ".jpg"
        out_suffix = ".jpg"
        mime = "image/jpeg"
    elif kind == "PNG":
        script_name = "PNG_Embed.py"
        in_suffix = ".png"
        out_suffix = ".png"
        mime = "image/png"
    else:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "detail": "Only JPEG and PNG images are supported for now."}
        )

    # write uploaded file to a temp input path with correct suffix
    in_fd, in_path = tempfile.mkstemp(suffix=in_suffix)
    os.close(in_fd)
    with open(in_path, "wb") as f:
        f.write(data)

    out_path = None
    try:
        # Build command to run the local embed script for the detected format
        script_path = os.path.join(os.path.dirname(__file__), script_name)

        mode_lower = mode.lower()

        if mode_lower == "embed":
            # random temp output file name (frontend does NOT specify it)
            out_fd, out_path = tempfile.mkstemp(suffix=out_suffix)
            os.close(out_fd)

            if not message:
                return JSONResponse(
                    status_code=400,
                    content={"status": "error", "detail": "Message is required for embedding."}
                )

            cmd = [
                sys.executable,
                script_path,
                "embed",
                in_path,
                out_path,
                message,
                password,
            ]

        elif mode_lower == "extract":
            cmd = [
                sys.executable,
                script_path,
                "extract",
                in_path,
                password,
            ]
        else:
            return JSONResponse(
                status_code=400,
                content={"status": "error", "detail": "Mode must be 'embed' or 'extract'."}
            )

        # run the CLI script and capture stdout/stderr
        proc = subprocess.run(cmd, capture_output=True, text=True)

        if proc.returncode != 0:
            tb = proc.stderr or proc.stdout or "Embed/extract tool failed"
            print(f"{script_name} stderr:", proc.stderr)
            return JSONResponse(
                status_code=500,
                content={"status":"error", "detail": tb}
            )

        # parse JSON-lines produced by the script (ignore non-json lines)
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        parsed = []
        for ln in lines:
            try:
                parsed.append(json.loads(ln))
            except json.JSONDecodeError:
                continue

        if mode_lower == "embed":
            meta = {}
            for obj in parsed:
                meta.update(obj)

            if not out_path or not os.path.exists(out_path):
                raise RuntimeError("Output file not found after embed.")

            with open(out_path, "rb") as f:
                stego_bytes = f.read()

            stego_b64 = base64.b64encode(stego_bytes).decode("ascii")

            return JSONResponse(
                content={
                    "status": "ok",
                    "mode": "embed",
                    "input_path": meta.get("input_path"),
                    "output_path": meta.get("output_path"),
                    "bytes_embedded": meta.get("bytes_embedded"),
                    "stego_image_b64": stego_b64,
                    "mime_type": mime,
                }
            )

        else:  # extract
            result_obj = parsed[-1] if parsed else {}
            return JSONResponse(
                content={
                    "status": "ok",
                    "mode": "extract",
                    **result_obj
                }
            )

    except Exception as e:
        tb = traceback.format_exc()
        print("Exception in /api/secret:", tb)
        return JSONResponse(
            status_code=500,
            content={"status": "error", "detail": str(e), "trace": tb}
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
