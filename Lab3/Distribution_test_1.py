from DistributionOfPowers_1 import *

# --- СЦЕНАРІЙ ТЕСТУВАННЯ ---
candidates = ["Alice", "Bob"]
rb = RegistrationBureau()
ec = ElectionCommission(candidates)
voters = [Voter(f"Voter_{i}") for i in range(1, 6)]

print("ЕТАП 1: Реєстрація")
for v in voters:
    v.get_registered(rb)

# Тестування подвійної реєстрації
print("\nСпроба повторної реєстрації Voter_1")
voters[0].get_registered(rb)

# Передача списків у ВК
print("\n[БР -> ВК] Передача списку валідних RN...")
ec.load_rn_list(rb.get_rn_list_for_ec())

print("\nЕТАП 2: Голосування")
# Чесне голосування 4 виборців
for v in voters[:4]:
    choice = random.choice(candidates)
    v.vote(choice, ec.public_key, ec)

# Тестування подвійного голосування
print("\nСпроба повторного голосування (Voter_1)")
# Voter_1 вже голосував вище. Пробує ще раз з тим самим RN, але новим ID
voters[0].vote("Bob", ec.public_key, ec, manual_id="999999")

print("\nГолосування з невалідним RN")
# Хтось намагається вгадати номер
fake_rn = 12345
print(f"Зловмисник пробує RN: {fake_rn}")
# Симулюємо відправку пакета вручну через метод vote з підміною RN
voters[4].vote("Alice", ec.public_key, ec, manual_rn=fake_rn)

# Voter_5 голосує чесно
print("\n[Voter_5] Голосує чесно...")
voters[4].vote("Alice", ec.public_key, ec)

print("\nЕТАП 3: Підрахунок та Перевірка")
results = ec.publish_results()
print("Результати опубліковано.")

# Перевірка виборцями
print("\nПеревірка голосів")
for v in voters:
    v.verify_my_vote(results)

# Симуляція фальсифікації для перевірки системи оповіщення
print("\n[СИМУЛЯЦІЯ ФАЛЬСИФІКАЦІЇ]")
print("Хакери підмінили голос Voter_1 в базі даних ВК...")
if len(ec.votes_db) > 0:
    # Знаходимо запис Voter_1 (за його ID)
    target_id = voters[0].id
    for record in ec.votes_db:
        if record['id'] == target_id:
            record['vote'] = "WRONG_CANDIDATE"  # Підміна

# Voter_1 перевіряє знову
voters[0].verify_my_vote(ec.publish_results())
