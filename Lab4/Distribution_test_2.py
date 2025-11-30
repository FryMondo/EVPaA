from DistributionOfPowers_2 import *

# --- ГОЛОВНИЙ СЦЕНАРІЙ ---
# 1. Ініціалізація
# Використовуємо складені числа для ID, щоб мати багато дільників
candidates = {24: "Alice", 60: "Bob"}
cec = CentralElectionCommission(candidates)
vc1 = ElectionCommission("VC-1")
vc2 = ElectionCommission("VC-2")

voters = [Voter(f"Voter_{i}") for i in range(1, 6)]

print("ЕТАП 1: Нормальне голосування")
# Voter_1 голосує за Alice (24)
voters[0].vote(24, cec.pub_key, vc1, vc2)
# Voter_2 голосує за Bob (60)
voters[1].vote(60, cec.pub_key, vc1, vc2)

print("\nЕТАП 2: Тестування")
# Voter_3 намагається проголосувати, але підробляє підпис
voters[2].vote(24, cec.pub_key, vc1, vc2, force_bad_sig=True)

print("\nЕТАП 3: Тестування")
# Voter_4 голосує за Alice (24). Система сама обере рандомні фактори.
# Це реалізовано всередині методу vote -> get_random_factors
voters[3].vote(24, cec.pub_key, vc1, vc2)

# Voter_5 голосує за Bob (60)
voters[4].vote(60, cec.pub_key, vc1, vc2)

# Отримуємо дані від комісій
data1 = vc1.publish_data()
data2 = vc2.publish_data()

print("\nЕТАП 4: Тестування")
# Симулюємо атаку ВК-1: Вона змінює частину бюлетеня Voter_5
target_id = voters[4].voter_id
if target_id in data1:
    print(f"[АТАКА] ВК-1 підміняє зашифровану частину бюлетеня для ID {target_id}")
    # Замінюємо валідний шифротекст на випадкове число
    data1[target_id] = 1234567

    # ЦВК підраховує
cec.tally_votes(data1, data2)
cec.show_results()
