from pathlib import Path

p = Path("main.py")
lines = p.read_text(encoding="utf-8").splitlines(keepends=True)

markers = [
    "Рџ", "Р ", "Рµ", "РЅ", "Р°", "Р»", "Рѕ", "Рї", "Рѕ",
    "СЃ", "С‚", "СЂ", "С‹", "СЏ", "СЌ", "С‡", "СЏ",
    "рџ", "вњ", "в–", "пё",
    "Гј", "Г§", "Г¶",
    "ж—Ґ", "жњ¬", "иЄћ"
]

def score(s):
    return sum(s.count(x) for x in markers)

changed = 0
old_score = 0
new_score = 0

out = []

for line in lines:
    before = score(line)

    if before:
        try:
            fixed = line.encode("cp1251").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            fixed = line

        after = score(fixed)

        if after < before:
            out.append(fixed)
            changed += 1
            old_score += before
            new_score += after
            continue

    out.append(line)
    old_score += before
    new_score += before

p.write_text("".join(out), encoding="utf-8")

print("=== SAFE MOJIBAKE REPAIR ===")
print("Changed lines:", changed)
print("Mojibake score before:", old_score)
print("Mojibake score after :", new_score)
print("Reduction:", old_score - new_score)
print("FILE WRITTEN: main.py")
