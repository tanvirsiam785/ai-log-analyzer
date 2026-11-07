import sys
from runner import Job


def show(record, status):
    meta = record["meta"]
    timing = "resumed" if record["resumed"] else f"{meta.get('seconds')}s"
    print(f"Chunk {record['chunk']}/{status['total']} "
          f"(lines {record['start']}-{record['end']}): {record['status']}, "
          f"{len(record['accepted'])} accepted, {len(record['rejected'])} rejected, "
          f"{timing}, RAM {status['ram_mb']} MB", flush=True)


if __name__ == "__main__":
    job = Job(sys.argv[1], ".", show)
    job.run()
    final = job.snapshot()
    print(final["state"], "-", final["message"])
    for r in final["report"]:
        print(f"  {r['severity']} {r['type']} {r['ip']} lines={r['lines']} | {r['evidence']}")