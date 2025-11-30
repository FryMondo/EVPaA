from BlindSignatureProtocol import *

# === ГОЛОВНИЙ СЦЕНАРІЙ ТЕСТУВАННЯ ===
candidates = ["A", "B"]
cec = CEC(candidates)

voters = [Voter(f"Voter_{i}", candidates) for i in range(1, 6)]

print("ЕТАП 1: Нормальне голосування (Voter_1)")
v1 = voters[0]
blinded_sets = v1.prepare_ballots(cec.pub_key)

check_indices, sign_idx = cec.request_signature(v1.name, blinded_sets)

factors = v1.reveal_factors(check_indices)

signed_blinded = cec.verify_and_sign(v1.name, blinded_sets, factors, sign_idx, check_indices)

v1.process_signed_set(signed_blinded, sign_idx, cec.pub_key)

v1.vote("A", cec)

print("\nЗаборона отримання другого набору (Voter_1)")
check_idx_2, sign_idx_2 = cec.request_signature(v1.name, blinded_sets)
if check_idx_2 is None:
    print("   -> Тест пройдено: ЦВК відмовила у видачі другого набору.")

print("\nЗаборона відправки двох бюлетенів (Voter_1)")
print(f"   -> Voter_1 пробує відправити другий бюлетень за 'B'...")
v1.vote("B", cec)

print("\nВиявлення некоректного бюлетеня (Voter_5 - Шахрай)")
v_cheat = voters[4]
blinded_sets_cheat = v_cheat.prepare_ballots(cec.pub_key, cheat_mode=True)

print(f"   -> {v_cheat.name} відправляє набори з підміною...")
check_indices, sign_idx = cec.request_signature(v_cheat.name, blinded_sets_cheat)

if 9 not in check_indices:
    print("   (Примусова заміна індексів для демо, щоб гарантовано потрапити на 'поганий' набір)")
    check_indices[0] = 9

factors_cheat = v_cheat.reveal_factors(check_indices)
result = cec.verify_and_sign(v_cheat.name, blinded_sets_cheat, factors_cheat, sign_idx, check_indices)

if result is None:
    print("   -> Тест пройдено: ЦВК виявила маніпуляцію і відмовила у підписі.")

cec.show_results()
