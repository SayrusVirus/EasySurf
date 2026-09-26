from pathlib import Path

files = [
    "main_before_cp1251_repair.py",
    "main_mojibake_current.py",
]

for name in files:
    p = Path(name)
    t = p.read_text(encoding="utf-8")

    markers = sum(t.count(x) for x in [
        "Рџ", "Р ", "СЃ", "Рµ",
        "рџ", "вњ", "в–", "пё",
        "Гј", "Г§"
    ])

    print(f"{name}:")
    print(f"  length  = {len(t)}")
    print(f"  markers = {markers}")
    print()

    for n, line in enumerate(t.splitlines(), 1):
        if any(x in line for x in ["РџР", "рџ", "вњ", "в–", "Гј", "ж—Ґ"]):
            print(f"  {n}: {line[:180]}")
            if n > 700:
                break
