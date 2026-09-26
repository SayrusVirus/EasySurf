from pathlib import Path

p = Path("main.py")
text = p.read_text(encoding="utf-8")

markers = (
    "Рџ", "Р ", "Рµ", "РЅ", "Р°", "СЃ", "С‚",
    "рџ", "вњ", "в–", "пё", "Гј", "Г§", "ж—Ґ", "жњ¬", "иЄћ"
)

def repair_segment(segment):
    if not any(m in segment for m in markers):
        return segment

    try:
        fixed = segment.encode("cp1251").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return segment

    return fixed

result = []
i = 0
changes = []

while i < len(text):
    ch = text[i]

    try:
        ch.encode("cp1251")
        start = i

        while i < len(text):
            try:
                text[i].encode("cp1251")
                i += 1
            except UnicodeEncodeError:
                break

        segment = text[start:i]
        fixed = repair_segment(segment)

        if fixed != segment:
            changes.append((segment[:120], fixed[:120]))
            result.append(fixed)
        else:
            result.append(segment)

    except UnicodeEncodeError:
        result.append(ch)
        i += 1

print("=== MOJIBAKE REPAIR DRY RUN ===")
print("Total candidate changes:", len(changes))
print()

for n, (old, new) in enumerate(changes[:30], 1):
    print(f"[{n}]")
    print("OLD:", old)
    print("NEW:", new)
    print()

print("No files were modified.")
