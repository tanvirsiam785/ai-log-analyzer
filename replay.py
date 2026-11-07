import sys
import json
from chunker import iter_chunks, load_tokenizer
from ledger import Ledger
from merger import build_report


def main(path):
    llm = load_tokenizer()
    ledger = Ledger()
    for chunk in iter_chunks(path, llm):
        ledger.add_chunk(chunk)

    with open("state.json", encoding="utf-8") as f:
        data = json.load(f)

    claims = []
    for record in data["records"]:
        for item in record["findings"]:
            if isinstance(item, dict):
                claims.append({**item, "chunks": [record["chunk"]]})

    report, dropped = build_report(claims, ledger)
    print("model claims", len(claims), "| reported", len(report), "| dropped IPs", len(dropped))
    print("--- reported")
    for x in report:
        tag = " (type corrected)" if x["reclassified"] else ""
        print(x["severity"], x["type"], x["ip"], x["lines"], "|", x["evidence"], tag, "|", x.get("link", ""))
    print("--- dropped")
    for d in dropped:
        print(d["ip"], d["claimed"], "|", d["why"])


if __name__ == "__main__":
    main(sys.argv[1])