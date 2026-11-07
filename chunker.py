import sys
import json
from llama_cpp import Llama

MODEL_PATH = "models/Qwen3.5-0.8B-Q4_K_M.gguf"
CHUNK_BUDGET = 900
MAX_LINE_CHARS = 400
OVERLAP_LINES = 2

BASE_KEYS = {"time", "app", "host", "service", "level", "client_ip",
             "request_id", "method", "path", "status",
             "response_bytes", "duration_ms", "user_agent"}

stats = {"lines": 0, "raw_tokens": 0, "compact_tokens": 0}


def short_ua(ua):
    if ua.startswith("Mozilla/5.0") and any(b in ua for b in ("Chrome/", "Safari/", "Firefox/")):
        return ""
    return ua[:40]


def compact(raw):
    try:
        d = json.loads(raw)
        if not isinstance(d, dict):
            return raw
    except ValueError:
        return raw

    parts = [
        str(d.get("time", ""))[5:19].replace("T", " "),
        f'{d.get("app", "")}/{d.get("service", "")}'.replace(" ", "_"),
        str(d.get("level", "")),
    ]
    if "client_ip" in d:
        parts.append(str(d["client_ip"]))
    if "method" in d or "path" in d:
        parts.append(f'{d.get("method", "")} {d.get("path", "")} {d.get("status", "")}')
    if "response_bytes" in d:
        parts.append(f'{d["response_bytes"]}B')
    if "duration_ms" in d:
        parts.append(f'{d["duration_ms"]}ms')
    ua = short_ua(str(d.get("user_agent", "")))
    if ua:
        parts.append("ua=" + ua)

    for k, v in d.items():
        if k in BASE_KEYS:
            continue
        if isinstance(v, list):
            v = ",".join(map(str, v))
        elif isinstance(v, dict):
            v = json.dumps(v, separators=(",", ":"))
        parts.append(f"{k}={v}")

    return " ".join(p for p in parts if p != "")


def load_tokenizer():
    return Llama(model_path=MODEL_PATH, vocab_only=True, verbose=False)


def count_tokens(llm, text):
    return len(llm.tokenize(text.encode("utf-8"), add_bos=False))


def make_chunk(lines):
    return {
        "start": lines[0][0],
        "end": lines[-1][0],
        "tokens": sum(x[2] for x in lines),
        "text": "\n".join(x[1] for x in lines),
    }


def iter_chunks(path, llm, budget=CHUNK_BUDGET, overlap=OVERLAP_LINES):
    cur = []
    cur_tokens = 0
    new_count = 0

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line_no, raw in enumerate(f, start=1):
            raw = raw.rstrip("\r\n")
            if not raw.strip():
                continue

            stats["lines"] += 1
            stats["raw_tokens"] += count_tokens(llm, raw)

            small = compact(raw)
            if len(small) > MAX_LINE_CHARS:
                small = small[:MAX_LINE_CHARS] + "...[cut]"

            text = f"[{line_no}] {small}"
            t = count_tokens(llm, text) + 1
            stats["compact_tokens"] += t

            if cur and new_count > 0 and cur_tokens + t > budget:
                yield make_chunk(cur)
                cur = cur[-overlap:] if overlap else []
                cur_tokens = sum(x[2] for x in cur)
                new_count = 0
                while cur and cur_tokens + t > budget:
                    cur_tokens -= cur.pop(0)[2]

            cur.append((line_no, text, t))
            cur_tokens += t
            new_count += 1

    if cur and new_count > 0:
        yield make_chunk(cur)


if __name__ == "__main__":
    path = sys.argv[1]
    llm = load_tokenizer()
    chunks = list(iter_chunks(path, llm))

    for i, c in enumerate(chunks, 1):
        print(f"Chunk {i}: lines {c['start']}-{c['end']}, {c['tokens']} tokens")

    print("---")
    print("Total chunks:", len(chunks))
    print("Max tokens in a chunk:", max(c["tokens"] for c in chunks))
    print("Log lines:", stats["lines"])
    print("Raw tokens:", stats["raw_tokens"], "| Compact tokens:", stats["compact_tokens"])
    print("Saved: {:.0f}%".format(100 * (1 - stats["compact_tokens"] / stats["raw_tokens"])))
    print("--- Chunk 1 preview ---")
    print("\n".join(chunks[0]["text"].split("\n")[:6]))