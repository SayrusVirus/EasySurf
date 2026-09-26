from pathlib import Path

p = Path("main.py")
t = p.read_text(encoding="utf-8")

repl = {
    '"View activity →": "РџРѕСЃРјРѕС‚СЂРµС‚СЊ Р°РєС‚РёРІРЅРѕСЃС‚СЊ →"':
    '"View activity →": "Посмотреть активность →"',

    '"View progress →": "РџРѕСЃРјРѕС‚СЂРµС‚СЊ РїСЂРѕРіСЂРµСЃСЃ →"':
    '"View progress →": "Посмотреть прогресс →"',

    '"Explore Earn →": "РџРµСЂРµР№С‚Рё Рє Р·Р°СЂР°Р±РѕС‚РєСѓ →"':
    '"Explore Earn →": "Перейти к заработку →"',

    '"Explore →": "РџРµСЂРµР№С‚Рё →"':
    '"Explore →": "Перейти →"',

    '"Yesterday": "жЁж—Ґ"':
    '"Yesterday": "Вчера"',
}

for old, new in repl.items():
    t = t.replace(old, new)

p.write_text(t, encoding="utf-8")
print("FINAL 5 LINES FIXED")
