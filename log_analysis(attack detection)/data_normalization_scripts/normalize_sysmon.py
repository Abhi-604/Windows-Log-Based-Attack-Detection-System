import xmltodict
import json
import os

INPUT_DIR = "datasets/sysmon-modular"
OUTPUT_DIR = "logs_raw/sysmon"

os.makedirs(OUTPUT_DIR, exist_ok=True)

for root, dirs, files in os.walk(INPUT_DIR):
    for f in files:
        if f.lower().endswith(".xml"):
            in_path = os.path.join(root, f)
            out_path = os.path.join(OUTPUT_DIR, f.replace(".xml", ".json"))

            try:
                with open(in_path, "r", encoding="latin-1", errors="ignore") as xml_file:
                    data = xmltodict.parse(xml_file.read())

                with open(out_path, "w", encoding="utf-8") as json_file:
                    json.dump(data, json_file, indent=2)

                print("[OK] Converted:", f)

            except Exception as e:
                print("[ERROR] Failed on:", f, "->", e)
