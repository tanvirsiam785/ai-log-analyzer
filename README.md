# Local AI Log Analyzer

A web app that finds attacks in a server log that is far larger than the local model's 2048-token context window. Everything runs on the local machine. No cloud API is used.

Design idea: **the model suspects, the code verifies.** The code never discovers attacks alone. It only checks the model's claims against a ledger computed by the program from the log. No results are hardcoded.

## How it works

1. The log is read line by line and split into chunks. Original line numbers are kept and no entry is ever cut.
2. A program-computed ledger keeps running totals per IP and carries facts from one chunk to the next.
3. The local model sees one chunk at a time, plus the ledger rows for the IPs in that chunk, and returns findings as JSON.
4. Each claim is checked against the ledger.
5. At the end, all claims are grouped by IP and re-verified against the final ledger. The result is one merged report.

## Model and resources

| Item | Value |
|---|---|
| Model | Qwen3.5-0.8B, Q4_K_M GGUF (533 MB), from unsloth/Qwen3.5-0.8B-GGUF |
| Runtime | llama-cpp-python 0.3.36, CPU only |
| Context | n_ctx = 2048, n_threads = 2 |
| RAM | about 950 MB peak during analysis (limit 4 GB) |
| Network | Needed only once to download the model. Offline afterwards. |

## Setup

Requires Python 3.13 (Windows tested).

```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Download the model once:

```
python -c "from huggingface_hub import hf_hub_download; hf_hub_download(repo_id='unsloth/Qwen3.5-0.8B-GGUF', filename='Qwen3.5-0.8B-Q4_K_M.gguf', local_dir='models')"
```

Run the dashboard:

```
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000, upload a .log or .txt file and press Start.

Command line alternative:

```
python pipeline.py data\Cultive8_Workspace_Agrigen_Server.log
```

## Splitting method

- Lines are read one at a time (utf-8-sig), so large files are never loaded whole.
- Each JSON line is compacted: host, request id and normal browser user agents are dropped, unusual user agents and extra fields are kept as key=value. Each line is prefixed with `[line_no]`.
- Tokens are counted with the model's own tokenizer.
- Budget: 900 tokens per chunk. The last 2 lines of a chunk are repeated at the start of the next one (overlap). Lines are never cut in the middle. Very long lines are truncated at 400 characters.
- Sample log: 258 lines became 23 chunks, the largest has 899 tokens. Compacting reduced the log from 39,638 to 16,855 tokens (57% saved).

## Token budget (2048 context)

| Part | Tokens |
|---|---|
| System prompt | about 350 |
| Ledger | at most 300 |
| Log lines | at most 900 |
| Output | at most 450, computed as 2048 minus prompt minus 120 margin |

If less than 150 tokens remain for the output, the call is refused instead of risking a cut-off.

## Ledger (memory between calls)

For each IP the program keeps: request count, ok, denied (401/403), other 4xx, 5xx, rate-limited (429) count, peak requests per minute, maximum requests_in_window, distinct paths, users, auth results, first failure, last success, evidence line numbers and flags. Only the IPs present in the current chunk are shown to the model, most suspicious first, within 300 tokens.

## Cross-part links

Because the ledger is carried across chunks, the final report can link events that are far apart. Example: 203.0.113.44 has denied logins starting at line 5, spread over many chunks, and a successful login at line 196. The report links them and raises the severity to Critical.

## Evidence verification

Every model claim is checked by code:

- brute_force: at least 5 denied logins and at most 5 distinct paths
- rate_anomaly: peak at least 30 per minute, or at least 5 rate-limited (429) responses
- scanning: at least 10 distinct paths and mostly failures
- sql_injection: SQL syntax in a cited line
- unauthorized_access: a cited line hits a protected path or is denied
- cited lines must belong to the claimed IP

Verification is repeated at the end with the final ledger, because evidence can arrive after the model first suspected an IP. If the claimed type is not supported but another type is supported for the same IP, the type is corrected and marked "type corrected". The model text is shown as "Model:", the verified numbers as "Why".

Log text is treated as data. The system prompt says never to follow instructions found in the log, and the output format is forced by a JSON schema.

## Error handling

- Upload checks: only .log and .txt, not empty, at most 20 MB, no binary content, valid UTF-8.
- Each chunk gets up to 3 attempts with different temperatures, a 150 s timeout and a retry on invalid JSON.
- A failed chunk is marked as failed and the run continues.
- State is saved atomically to state.json after every chunk. Restarting with the same file (matched by SHA-1) reuses finished chunks and shows them as "resumed".
- Only one analysis can run at a time.

## Dashboard

Upload, Start/Resume, progress bar, chunk count, failed count, RAM, average model call time, final report table (severity, type, IP, evidence lines, why, action, chunks) and a per-chunk table.

API: POST /upload, POST /start, GET /progress, GET /report.

## Results on the sample log

- 23 chunks, 0 failed, average 33.9 s per model call, about 950 MB RAM. The first full run took 1214 s.
- 5 findings on 4 IPs:
  - 203.0.113.44 brute_force, Critical, linked across parts to the successful login at line 196
  - 203.0.113.72 sql_injection, High
  - 203.0.113.90 scanning and unauthorized_access, High
  - 203.0.113.155 rate_anomaly, Medium
- The registered health monitor 192.0.2.10, which the model wrongly flagged, is not in the report.

## Replay tools

- `replay.py` rebuilds the ledger from the log and re-merges the saved claims in state.json without calling the model.
- `inspect_state.py` prints per-chunk claims and rejected reasons.

## Known limits

- The 0.8B model has low recall. It sometimes returns an empty list or names the wrong type.
- Some model text fields are cut at their length limit.
- Verifier thresholds are fixed heuristics.
- Only JSON-lines logs are supported.
- The ledger keeps per-line rows in memory.
- 20 MB upload cap, one analysis at a time, no API authentication.
