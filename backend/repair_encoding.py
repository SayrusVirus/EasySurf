from pathlib import Path

p = Path("main.py")
text = p.read_text(encoding="utf-8")

for _ in range(3):
    try:
        fixed = text.encode("latin1").decode("utf-8")
    except UnicodeError:
        break
    if len(fixed) >= len(text):
        break
    text = fixed

p.write_text(text, encoding="utf-8")
print("ENCODING REPAIR DONE")
