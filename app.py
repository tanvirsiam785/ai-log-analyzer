import os
import threading
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from runner import Job, REPORT_NAME
from validate import validate_upload, MAX_BYTES

UPLOAD_DIR = "uploads"
TARGET = os.path.join(UPLOAD_DIR, "current.log")
TEMP = os.path.join(UPLOAD_DIR, "incoming.tmp")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = FastAPI()
current = {"job": None, "thread": None, "name": "current.log"}


def running():
    thread = current["thread"]
    return thread is not None and thread.is_alive()


def drop_temp():
    if os.path.exists(TEMP):
        os.remove(TEMP)


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    if running():
        raise HTTPException(status_code=409, detail="An analysis is running")
    name = file.filename or ""
    size = 0
    too_big = False
    with open(TEMP, "wb") as out:
        while True:
            block = await file.read(1048576)
            if not block:
                break
            size += len(block)
            if size > MAX_BYTES:
                too_big = True
                break
            out.write(block)
    if too_big:
        drop_temp()
        raise HTTPException(status_code=400, detail="The file is larger than 20 MB")
    ok, message = validate_upload(TEMP, name)
    if not ok:
        drop_temp()
        raise HTTPException(status_code=400, detail=message)
    os.replace(TEMP, TARGET)
    current["name"] = name
    current["job"] = None
    current["thread"] = None
    return {"ok": True, "name": name, "size": size}


@app.post("/start")
def start():
    if running():
        raise HTTPException(status_code=409, detail="An analysis is already running")
    if not os.path.exists(TARGET):
        raise HTTPException(status_code=400, detail="Upload a log file first")
    job = Job(TARGET, ".")
    thread = threading.Thread(target=job.run, daemon=True)
    current["job"] = job
    current["thread"] = thread
    thread.start()
    return {"ok": True}


@app.get("/progress")
def progress():
    base = {"uploaded": os.path.exists(TARGET), "name": current["name"]}
    job = current["job"]
    if job is None:
        return {**base, "state": "idle", "message": "", "total": 0, "done": 0,
                "failed": 0, "ram_mb": 0, "chunks": [], "report": []}
    snap = job.snapshot()
    snap["chunks"] = [
        {
            "chunk": c["chunk"],
            "start": c["start"],
            "end": c["end"],
            "status": c["status"],
            "resumed": c.get("resumed", False),
            "seconds": c.get("meta", {}).get("seconds"),
            "accepted": len(c["accepted"]),
            "rejected": len(c["rejected"]),
            "errors": c.get("errors", []),
        }
        for c in snap["chunks"]
    ]
    return {**base, **snap}


@app.get("/report")
def report():
    if not os.path.exists(REPORT_NAME):
        raise HTTPException(status_code=404, detail="No report yet")
    return FileResponse(REPORT_NAME, media_type="application/json", filename="report.json")


app.mount("/", StaticFiles(directory="static", html=True), name="static")