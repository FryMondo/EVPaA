from SupportingFunctions.RSA_functions import *
from SupportingFunctions.EDS_functions import *

# "Сире" шифрування для збереження гомоморфних властивостей
def encrypt_raw(message_int, public_key):
    # m^e mod n
    e, n = public_key
    return pow(message_int, e, n)


def decrypt_raw(cipher_int, private_key):
    d, n = private_key
    return pow(cipher_int, d, n)


# Допоміжна функція факторизації
def get_random_factors(number):
    factors = []
    for i in range(1, int(number ** 0.5) + 1):
        if number % i == 0:
            factors.append((i, number // i))
    return random.choice(factors)


# --- Учасники ---
class Voter:
    def __init__(self, name):
        self.name = name
        self.pub_key, self.priv_key = generate_keypair(100, 500)
        self.voter_id = random.randint(10000, 99999)  # Анонімний ID

    def vote(self, candidate_id, cec_pub_key, vc1, vc2, force_bad_sig=False):
        # 1. Розбиття ID на множники
        m1, m2 = get_random_factors(candidate_id)
        print(f"[{self.name}] Голосує за ID {candidate_id}. Розбито на: {m1} * {m2}")

        # 2. Шифрування множників ключем ЦВК
        c1 = encrypt_raw(m1, cec_pub_key)
        c2 = encrypt_raw(m2, cec_pub_key)

        # 3. Підготовка пакетів для ВК
        # Пакет: "VoterID:EncryptedPart"
        msg1 = f"{self.voter_id}:{c1}"
        msg2 = f"{self.voter_id}:{c2}"

        # 4. Підпис
        sig_key = self.priv_key
        if force_bad_sig:
            # Використовуємо чужий/випадковий ключ для симуляції підробки
            fake_keys = generate_keypair(100, 500)
            sig_key = fake_keys[1]

        sig1 = sign_hash(msg1, sig_key)
        sig2 = sign_hash(msg2, sig_key)

        # 5. Відправка
        vc1.receive_part(self.name, self.voter_id, c1, sig1, self.pub_key)
        vc2.receive_part(self.name, self.voter_id, c2, sig2, self.pub_key)


class ElectionCommission:
    def __init__(self, name):
        self.name = name
        self.storage = {}  # {voter_id: encrypted_part}
        self.received_voters = set()

    def receive_part(self, voter_name, voter_id, encrypted_part, signature, voter_pub_key):
        # Формуємо рядок для перевірки підпису
        msg = f"{voter_id}:{encrypted_part}"

        # Перевірка ЕЦП
        if not verify_signature(msg, signature, voter_pub_key):
            print(f"[{self.name}] ПОМИЛКА: Невірний підпис від {voter_name}! Бюлетень відхилено.")
            return False

        # Збереження
        self.storage[voter_id] = encrypted_part
        self.received_voters.add(voter_name)
        print(f"[{self.name}] Частина бюлетеня від {voter_name} (ID: {voter_id}) прийнята.")
        return True

    def publish_data(self):
        return self.storage


class CentralElectionCommission:
    def __init__(self, candidates):
        self.pub_key, self.priv_key = generate_keypair(100, 500)
        self.candidates = candidates  # {ID: Name}
        self.final_votes = {name: 0 for name in candidates.values()}
        self.spoilt_ballots = 0

    def tally_votes(self, data_vc1, data_vc2):
        print("\n--- ЦВК: Обробка голосів ---")
        all_ids = set(data_vc1.keys()).union(set(data_vc2.keys()))

        for vid in all_ids:
            if vid not in data_vc1 or vid not in data_vc2:
                print(f"[ЦВК] ID {vid}: Неповний комплект частин. Пропуск.")
                continue

            c1 = data_vc1[vid]
            c2 = data_vc2[vid]

            # Гомоморфна властивість RSA: C1 * C2 = (m1^e) * (m2^e) = (m1*m2)^e mod n

            print(f"[ЦВК] З'єднання частин для ID {vid} (множення шифротекстів)...")
            c_final = (c1 * c2) % self.pub_key[1]  # pub_key[1] це модуль n

            print(f"[ЦВК] Розшифрування об'єднаного бюлетеня...")
            decrypted_candidate_id = decrypt_raw(c_final, self.priv_key)

            # Перевірка результату
            cand_name = self.candidates.get(decrypted_candidate_id)

            if cand_name:
                self.final_votes[cand_name] += 1
                print(f"   -> Результат: {decrypted_candidate_id} ({cand_name}). ЗАРАХОВАНО.")
            else:
                self.spoilt_ballots += 1
                print(
                    f"   -> Результат: {decrypted_candidate_id}. Кандидат не знайдений (ЗІПСОВАНИЙ БЮЛЕТЕНЬ).")

    def show_results(self):
        print(f"\nРЕЗУЛЬТАТИ: {self.final_votes}")
        print(f"Зіпсованих бюлетенів: {self.spoilt_ballots}")
