from ProtocolWithoutCommission import *

# 1. Ініціалізація
participants = [Voter(n) for n in ["A", "B", "C", "D", "E"]]
candidates = ["Alice", "Bob"]

print("ЕТАП 1: Генерація та шифрування (Onion)")
initial_ballots = []

for v in participants:
    choice = random.choice(candidates)
    # Кожен шифрує для ланцюжка A->B->C->D->E
    onion = v.create_onion_ballot(choice, participants)
    initial_ballots.append(onion)
    print(f"Виборець {v.name} проголосував.")

# Пакет для передачі
current_batch = {'ballots': initial_ballots, 'signature': 0}
prev_key = None  # На вході А підпису немає

print("\nЕТАП 2: Mix-Net (Передача по колу)")

# Ланцюжок обробки
chain = participants  # A -> B -> C -> D -> E

# -------------------------------------------------------------
# НАЛАШТУВАННЯ ТЕСТІВ
TEST_ATTACK_MODIFICATION = False  # Завдання 2.a (Підміна)
TEST_ATTACK_DELETION = False  # Завдання 2.b (Вилучення)
# -------------------------------------------------------------

# СИМУЛЯЦІЯ АТАКИ (ДОДАВАННЯ/ВИЛУЧЕННЯ) перед A
if TEST_ATTACK_DELETION:
    print("\nЗловмисник додає фальшивий бюлетень перед передачею до A!")
    current_batch['ballots'].append("FAKE_BALLOT_12345")

for i, processor in enumerate(chain):
    print(f"\n--- Черга виборця {processor.name} ---")

    # СИМУЛЯЦІЯ АТАКИ (ПІДМІНА) перед C
    if TEST_ATTACK_MODIFICATION and processor.name == "C":
        print("[АТАКА 2.a] Зловмисник псує один бюлетень перед передачею до C!")
        target = current_batch['ballots'][0]
        # Замінюємо один символ у блоці шифротексту
        if len(target) > 5:
            # Просто замінюємо частину рядка
            corrupted = "99999" + target[5:]
            current_batch['ballots'][0] = corrupted

    # Обробка
    result = processor.process_batch(current_batch, prev_key)

    if result is None:
        print("Протокол перервано через помилку підпису.")
        break

    current_batch = result
    prev_key = processor.pub

print("\nЕТАП 3: Підрахунок результатів")
final_votes = current_batch['ballots']
tally = {c: 0 for c in candidates}
tally['INVALID/CORRUPTED'] = 0

for v in final_votes:
    if v in tally:
        tally[v] += 1
    else:
        tally['INVALID/CORRUPTED'] += 1

print(f"Результати: {tally}")
