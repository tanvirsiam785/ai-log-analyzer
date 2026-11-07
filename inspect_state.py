import json

with open("state.json", encoding="utf-8") as f:
    data = json.load(f)

for r in data["records"]:
    print("chunk", r["chunk"], r["start"], r["end"], r["status"], r["errors"])
    for item in r["findings"]:
        print("   claim", item.get("type"), item.get("ip"), item.get("lines"))
    for item in r["rejected"]:
        print("   rejected", item["type"], item["ip"], item["why"])