import os
import json

INPUT_DIR = "datasets/atomic-red-team"
OUTPUT_DIR = "logs_raw/atomic"

os.makedirs(OUTPUT_DIR, exist_ok=True)

for root, dirs, files in os.walk(INPUT_DIR):
    for f in files:
        full_path = os.path.join(root, f)

        # Normalize .txt and .log
        if f.endswith(".txt") or f.endswith(".log"):
            out_path = os.path.join(OUTPUT_DIR, f + ".jsonl")
            try:
                with open(full_path, "r", encoding="latin-1", errors="ignore") as infile, \
                     open(out_path, "w", encoding="utf-8") as outfile:

                    for line in infile:
                        if line.strip():
                            json.dump({"event": line.strip()}, outfile)
                            outfile.write("\n")

                print("[OK] Converted TXT/LOG:", f)

            except Exception as e:
                print("[ERROR TXT]", f, e)

        # Normalize .json logs
        elif f.endswith(".json"):
            out_path = os.path.join(OUTPUT_DIR, f)
            try:
                with open(full_path, "r", encoding="latin-1", errors="ignore") as infile:
                    data = infile.read()

                with open(out_path, "w", encoding="utf-8") as outfile:
                    outfile.write(data)

                print("[OK] Copied JSON:", f)

            except Exception as e:
                print("[ERROR JSON]", f, e)
