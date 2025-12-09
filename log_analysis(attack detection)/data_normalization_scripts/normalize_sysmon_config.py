import os
import json
import xmltodict

INPUT_DIR = "datasets/sysmon-config"
OUTPUT_DIR = "logs_raw/sysmon_config"

os.makedirs(OUTPUT_DIR, exist_ok=True)

for root, dirs, files in os.walk(INPUT_DIR):
    for f in files:
        full_path = os.path.join(root, f)

        # Normalize XML logs
        if f.lower().endswith(".xml"):
            out_path = os.path.join(OUTPUT_DIR, f.replace(".xml", ".json"))
            try:
                with open(full_path, "r", encoding="latin-1", errors="ignore") as xml_file:
                    data = xmltodict.parse(xml_file.read())
                
                with open(out_path, "w", encoding="utf-8") as j:
                    json.dump(data, j, indent=2)

                print("[OK] Converted XML:", f)

            except Exception as e:
                print("[ERROR XML]", f, e)

        # Normalize text logs
        elif f.lower().endswith(".txt") or f.lower().endswith(".log"):
            out_path = os.path.join(OUTPUT_DIR, f + ".jsonl")
            try:
                with open(full_path, "r", encoding="latin-1", errors="ignore") as infile, \
                     open(out_path, "w", encoding="utf-8") as outfile:

                    for line in infile:
                        if line.strip():
                            json.dump({"event": line.strip()}, outfile)
                            outfile.write("\n")

                print("[OK] Converted TXT:", f)

            except Exception as e:
                print("[ERROR TXT]", f, e)
