from presidio_analyzer import AnalyzerEngine
import os
import json

analyzer = AnalyzerEngine()

results = []

FILE_EXTENSIONS = (
    ".java", ".sql", ".yml", ".yaml",
    ".properties", ".sh", ".md", ".txt"
)

SCAN_DIR = "target-repo"

for root, _, files in os.walk(SCAN_DIR):
    for file in files:
        if file.endswith(FILE_EXTENSIONS):
            path = os.path.join(root, file)

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()

                findings = analyzer.analyze(
                    text=text,
                    language="en",
                    entities=[
                        "PERSON",
                        "EMAIL_ADDRESS",
                        "PHONE_NUMBER",
                        "DATE_TIME",
                        "IP_ADDRESS",
                        "LOCATION"
                    ]
                )

                for r in findings:
                    results.append({
                        "file": path.replace(SCAN_DIR + "/", ""),
                        "entity": r.entity_type,
                        "start": r.start,
                        "end": r.end,
                        "confidence": round(r.score, 2)
                    })

            except Exception as e:
                print(f"Skipping {path}: {e}")

with open("presidio-report.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"Presidio scan complete. Findings: {len(results)}")
