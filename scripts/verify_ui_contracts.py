import re
from pathlib import Path

FRONTEND_SRC = Path(__file__).resolve().parent.parent / "frontend" / "src"

def audit_ui():
    print("=== AUDITING FRONTEND SOURCE FILES FOR FAKE / MARKETING COPY ===")
    prohibited_strings = [
        "Welcome to ADFIR",
        "211",
        "local-user",
        "Cores | Linux",
        "AI-Assisted Digital Forensic Investigation Platform",
        "fake",
        "mock"
    ]
    
    found_issues = []
    for p in FRONTEND_SRC.rglob("*.tsx"):
        content = p.read_text(encoding="utf-8")
        for s in prohibited_strings:
            if s.lower() in content.lower():
                found_issues.append(f"{p.name}: contains '{s}'")

    if found_issues:
        print("Issues found:")
        for iss in found_issues:
            print(" -", iss)
    else:
        print("Clean! Zero prohibited marketing/fake strings detected across frontend.")

if __name__ == "__main__":
    audit_ui()
