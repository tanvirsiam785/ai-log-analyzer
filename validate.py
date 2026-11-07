import os
import codecs

ALLOWED = (".log", ".txt")
MAX_BYTES = 20 * 1024 * 1024
SAMPLE = 8192


def validate_upload(path, original_name):
    if not original_name.lower().endswith(ALLOWED):
        return False, "Only .log and .txt files are accepted"
    size = os.path.getsize(path)
    if size == 0:
        return False, "The file is empty"
    if size > MAX_BYTES:
        return False, "The file is larger than 20 MB"
    with open(path, "rb") as f:
        head = f.read(SAMPLE)
    if b"\x00" in head:
        return False, "The file looks binary"
    try:
        text = codecs.getincrementaldecoder("utf-8-sig")().decode(head, final=False)
    except UnicodeDecodeError:
        return False, "The file is not valid UTF-8 text"
    if not text.strip():
        return False, "The file has no content"
    return True, ""