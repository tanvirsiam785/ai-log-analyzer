import os
import json
import time
import hashlib
import threading
import psutil
from llama_cpp import Llama
from chunker import iter_chunks, count_tokens, MODEL_PATH
from analyzer import analyze_chunk, CTX
from ledger import Ledger
from merger import verify, build_report

LEDGER_BUDGET = 300
MAX_ATTEMPTS = 3
CALL_TIMEOUT = 150
TEMPERATURES = [0.1, 0.3, 0.5]
STATE_NAME = "state.json"
REPORT_NAME = "report.json"


def file_id(path):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1048576), b""):
            h.update(block)
    return h.hexdigest()


class Job:
    def __init__(self, path, work_dir=".", callback=None):
        self.path = path
        self.state_file = os.path.join(work_dir, STATE_NAME)
        self.report_file = os.path.join(work_dir, REPORT_NAME)
        self.callback = callback
        self.lock = threading.Lock()
        self.status = {"state": "idle", "message": "", "total": 0,
                       "done": 0, "failed": 0, "ram_mb": 0}
        self.records = []
        self.report = []
        self.dropped = []

    def snapshot(self):
        with self.lock:
            return {**self.status, "chunks": list(self.records),
                    "report": list(self.report), "dropped": list(self.dropped)}

    def set_status(self, **values):
        with self.lock:
            self.status.update(values)

    def load_saved(self, fid):
        try:
            with open(self.state_file, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return {}
        if not isinstance(data, dict) or data.get("file_id") != fid:
            return {}
        return {r["chunk"]: r for r in data.get("records", [])
                if isinstance(r, dict) and "chunk" in r}

    def save(self, fid):
        tmp = self.state_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"file_id": fid, "records": self.records}, f)
        os.replace(tmp, self.state_file)

    def run(self):
        try:
            self.execute()
        except Exception as exc:
            self.set_status(state="error", message=str(exc))

    def analyze(self, llm, ledger, chunk, number, count):
        memory = ledger.render(chunk, LEDGER_BUDGET, count)
        errors = []
        findings = None
        meta = {}
        for attempt in range(MAX_ATTEMPTS):
            error = ""
            try:
                parsed, raw, meta = analyze_chunk(
                    llm, chunk, memory, TEMPERATURES[attempt], CALL_TIMEOUT)
                if meta["finish_reason"] == "timeout":
                    error = "timeout"
                elif isinstance(parsed, dict) and isinstance(parsed.get("findings"), list):
                    findings = parsed["findings"]
                else:
                    error = "invalid json"
            except ValueError as exc:
                errors.append(str(exc))
                break
            except Exception as exc:
                error = str(exc)
            if findings is not None:
                break
            errors.append(error)
            time.sleep(1)

        accepted = []
        rejected = []
        for item in findings or []:
            clean, why = verify(item, ledger)
            if clean is None:
                rejected.append({
                    "ip": item.get("ip") if isinstance(item, dict) else None,
                    "type": item.get("type") if isinstance(item, dict) else None,
                    "why": why,
                })
                continue
            clean["chunks"] = [number]
            accepted.append(clean)

        return {
            "chunk": number,
            "start": chunk["start"],
            "end": chunk["end"],
            "status": "ok" if findings is not None else "failed",
            "errors": errors,
            "meta": meta,
            "findings": findings or [],
            "accepted": accepted,
            "rejected": rejected,
        }

    def execute(self):
        self.set_status(state="running", message="loading model")
        llm = Llama(model_path=MODEL_PATH, n_ctx=CTX, n_threads=2, verbose=False)
        fid = file_id(self.path)
        saved = self.load_saved(fid)

        self.set_status(message="splitting log")
        chunks = list(iter_chunks(self.path, llm))
        self.set_status(total=len(chunks), message="analyzing")

        def count(text):
            return count_tokens(llm, text)

        ledger = Ledger()
        process = psutil.Process()
        failed = 0

        for number, chunk in enumerate(chunks, start=1):
            ledger.add_chunk(chunk)
            previous = saved.get(number)
            if previous and previous.get("status") == "ok":
                record = {**previous, "resumed": True}
            else:
                record = {**self.analyze(llm, ledger, chunk, number, count), "resumed": False}

            if record["status"] != "ok":
                failed += 1
            for item in record["accepted"]:
                ledger.flag(item["ip"], item["type"])

            with self.lock:
                self.records.append(record)
            self.save(fid)
            self.set_status(done=number, failed=failed,
                            ram_mb=process.memory_info().rss // 1048576)
            if self.callback:
                self.callback(record, self.status)

        claims = []
        for record in self.records:
            for item in record["findings"]:
                if isinstance(item, dict):
                    claims.append({**item, "chunks": [record["chunk"]]})
        report, dropped = build_report(claims, ledger)
        with self.lock:
            self.report = report
            self.dropped = dropped
        with open(self.report_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        message = f"{failed} chunks failed" if failed else "completed"
        self.set_status(state="done", message=message)