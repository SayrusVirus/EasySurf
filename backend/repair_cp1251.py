from pathlib import Path

p = Path("main.py")
text = p.read_text(encoding="utf-8")

for _ in range(3):
    try:
        fixed = text.encode("cp1251").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        break

    if fixed == text:
        break

    text = fixed

p.write_text(text, encoding="utf-8")
print("CP1251 UTF8 REPAIR DONE")
