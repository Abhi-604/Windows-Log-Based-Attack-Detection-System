import os
import json

INPUT_DIR = "datasets/ossec-hids"
OUTPUT_DIR = "logs_raw/ossec"

os.makedirs(OUTPUT_DIR, exist_ok=True)

for root, dirs, files in os.walk(INPUT_DIR):
    for f in files:
        if f.endswith(".log") or f.endswith(".txt"):
            in_path = os.path.join(root, f)
            out_path = os.path.join(OUTPUT_DIR, f + ".jsonl")

            with open(in_path, "r", encoding="latin-1", errors="ignore") as infile, \
                 open(out_path, "w", encoding="utf-8") as outfile:

                for line in infile:
                    line = line.strip()
                    if line:
                        json.dump({"event": line}, outfile)
                        outfile.write("\n")

            print("[OK] Converted:", f)
