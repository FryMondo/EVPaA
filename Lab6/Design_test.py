from ProtocolDesign import *

# --- Ініціалізація системи ---
candidates = {100: "Alice", 200: "Bob"}

# 1. ЦВК
cec = CEC(candidates)

# 2. ВК Середнього рівня
mlc1 = MLC("MLC-1 (District A)", cec.pub)
mlc2 = MLC("MLC-2 (District B)", cec.pub)

# 3. ВК Низького рівня
# LLC 1,2 -> MLC 1
llc1 = LLC("LLC-1", mlc1)
llc2 = LLC("LLC-2", mlc1)
# LLC 3,4 -> MLC 2
llc3 = LLC("LLC-3", mlc2)
llc4 = LLC("LLC-4", mlc2)

# Реєстрація (Сліпий підпис)
print("ЕТАП 1: Реєстрація")
voters = [Voter(f"Voter-{i}") for i in range(1, 6)]
for v in voters:
    v.register(cec)

# Голосування (Розділення і Відправка)
print("\nЕТАП 2: Голосування")

# Виборці 1, 2, 3 голосують у Дистрикті А (через LLC-1/2 -> MLC-1)
voters[0].vote(100, llc1, llc2, mlc1.pub)  # За Alice
voters[1].vote(200, llc1, llc2, mlc1.pub)  # За Bob
voters[2].vote(100, llc1, llc2, mlc1.pub)  # За Alice

# Виборці 4, 5 голосують у Дистрикті B (через LLC-3/4 -> MLC-2)
voters[3].vote(200, llc3, llc4, mlc2.pub)  # За Bob
voters[4].vote(100, llc3, llc4, mlc2.pub)  # За Alice

# Збір та передача даних (LLC -> MLC)
print("\nЕТАП 3: Передача даних LLC -> MLC")
# LLC передають накопичені буфери
llc1.push_to_mlc(part_num=1)
llc2.push_to_mlc(part_num=2)

llc3.push_to_mlc(part_num=1)
llc4.push_to_mlc(part_num=2)

# Обробка в MLC (Відновлення та підрахунок)
print("\nЕТАП 4: Обробка в MLC")
results_mlc1 = mlc1.process_votes()
results_mlc2 = mlc2.process_votes()

# --- ТЕСТУВАННЯ ЗАГРОЗ ---
print("\nТЕСТУВАННЯ ЗАГРОЗ")

# Загроза 1: Спроба подвійного голосування (Voter-1 пробує проголосувати ще раз у MLC-2)
print("[TEST] Voter-1 намагається проголосувати вдруге в іншому окрузі...")
# Симулюємо пряму відправку в LLC3/4
# Voter-1 використовує той самий signed_token
p1, p2 = split_secret(200)  # Пробує за Bob
fake_enc1 = encrypt(p1, mlc2.pub)

# Відправляємо тільки в LLC-3 (імітуємо, що LLC-4 не отримав або отримав пізніше)
# Або відправляємо повноцінно
llc3.receive_ballot_part(voters[0].token, voters[0].signed_token, fake_enc1)
llc3.push_to_mlc(part_num=1)

# Загроза 2: Підміна даних на рівні LLC (Man-in-the-Middle / Corrupt LLC)
print("[TEST] LLC-4 корумпована і підміняє частину бюлетеня Voter-5...")
# Voter-5 голосував за Alice (100).
# LLC-4 має отримати частину 2.
# Ми вручну "зіпсуємо" дані в буфері перед відправкою, якби ми це робили в реальному часі.
# Але зараз ми просто відправимо "сміття" від імені LLC-4.

# Очистимо поточний буфер LLC4 (там чесний голос Voter-5), щоб замінити його
llc4.buffer = []

# Створюємо фейк
fake_part = 999999
fake_enc_part = encrypt(fake_part, mlc2.pub)
llc4.receive_ballot_part(voters[4].token, voters[4].signed_token, fake_enc_part)
llc4.push_to_mlc(part_num=2)

# Перерахунок MLC-2 після атак
print("[MLC-2] Повторна обробка з урахуванням атак...")
results_mlc2_updated = mlc2.process_votes()

# --- ЦВК ---
# ЦВК отримує валідні результати від MLC-1 і "результати з атаками" від MLC-2
cec.receive_results(results_mlc1)
cec.receive_results(results_mlc2_updated)

cec.publish_results()
