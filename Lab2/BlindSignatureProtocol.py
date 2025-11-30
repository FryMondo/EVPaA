import hashlib
from SupportingFunctions.RSA_functions import *
from SupportingFunctions.Blind_RSA_Signature import *


def string_to_int(message_str):
    # Перетворення рядка в число (через хеш, щоб вміститися в n)
    # Використовуємо частину хешу для гарантії m < n
    h = hashlib.sha256(message_str.encode()).hexdigest()
    return int(h, 16) % (10 ** 5)


def verify_signature(message_int, signature, pub_key):
    # s^e mod n == m
    e, n = pub_key
    check = pow(signature, e, n)
    return check == message_int


# --- Класи Протоколу ---
class Voter:
    def __init__(self, name, candidates):
        self.name = name
        self.candidates = candidates
        self.id = random.randint(1000, 9999)  # Унікальний ID
        self.sets = []  # Тут будуть зберігатися всі дані (r, повідомлення)
        self.blinded_sets = []  # Те, що відправляється у ЦВК
        self.final_signature = None
        self.final_ballot = None

    def prepare_ballots(self, cec_pub_key, cheat_mode=False):
        # Генерує 10 наборів бюлетенів
        # cheat_mode=True створює "поганий" набір для тестування
        self.sets = []
        self.blinded_sets = []

        for i in range(10):
            current_set_data = []
            current_blinded_set = []

            # Стандартний набір: по одному бюлетеню за кожного кандидата
            cands_to_use = self.candidates.copy()

            # Якщо режим шахрайства, в останньому наборі робимо два голоси за кандидата А
            if cheat_mode and i == 9:
                cands_to_use = [self.candidates[0], self.candidates[0]]

            for cand in cands_to_use:
                # Бюлетень: "ID:Vote"
                msg_str = f"{self.id}:{cand}"
                msg_int = string_to_int(msg_str)

                # Маскування
                blinded_val, r = blind_message(msg_int, cec_pub_key)

                # Зберігаємо r та msg_int для себе (щоб потім зняти маску або показати ЦВК)
                current_set_data.append({'r': r, 'msg_int': msg_int, 'msg_str': msg_str})
                current_blinded_set.append(blinded_val)

            self.sets.append(current_set_data)
            self.blinded_sets.append(current_blinded_set)

        return self.blinded_sets

    def reveal_factors(self, indices):
        # Відкриває множники r для вказаних індексів наборів
        factors = []
        for idx in indices:
            set_factors = []
            for item in self.sets[idx]:
                set_factors.append({'r': item['r'], 'msg_str': item['msg_str']})
            factors.append(set_factors)
        return factors

    def process_signed_set(self, signed_blinded_set, set_index, cec_pub_key):
        # Знімаємо маску з підписаного набору
        my_set_data = self.sets[set_index]
        self.decrypted_ballots = []

        for i in range(len(signed_blinded_set)):
            s_blind = signed_blinded_set[i]
            r = my_set_data[i]['r']
            msg_str = my_set_data[i]['msg_str']
            msg_int = my_set_data[i]['msg_int']

            # Розмаскування
            signature = unblind_signature(s_blind, r, cec_pub_key)
            self.decrypted_ballots.append(
                {'candidate': msg_str.split(':')[1], 'signature': signature, 'msg_int': msg_int, 'msg_str': msg_str})

    def vote(self, candidate_name, cec):
        # Вибір одного бюлетеня і відправлення
        chosen_ballot = next((b for b in self.decrypted_ballots if b['candidate'] == candidate_name), None)
        if chosen_ballot:
            # Шифрування для транспортування
            # Передаємо: ID (всередині msg), Підпис, Повідомлення
            print(f"   -> {self.name} відправляє голос за {candidate_name} (ID: {self.id})")
            cec.receive_vote(chosen_ballot['msg_str'], chosen_ballot['signature'])
        else:
            print(f"Помилка: бюлетень за {candidate_name} не знайдено.")


class CEC:
    def __init__(self, candidates):
        self.candidates = candidates
        self.pub_key, self.priv_key = generate_keypair(100, 300)
        self.votes = {cand: 0 for cand in candidates}
        self.received_ids = set()  # Для перевірки на подвійне голосування
        self.signed_voters = set()  # Хто вже отримав підпис

    def request_signature(self, voter_name, blinded_sets):
        print(f"[ЦВК] Отримано запит на підпис від {voter_name} (10 наборів).")

        # 1. Перевірка права на підпис
        if voter_name in self.signed_voters:
            print(f"[ЦВК] ВІДМОВА: Виборець {voter_name} вже отримував бюлетені!")
            return None, None

        # 2. Вибір 9 наборів для перевірки
        all_indices = list(range(10))
        check_indices = random.sample(all_indices, 9)
        sign_index = list(set(all_indices) - set(check_indices))[0]

        return check_indices, sign_index

    def verify_and_sign(self, voter_name, blinded_sets, factors, sign_index, check_indices):
        # 3. Перевірка 9 наборів
        # factors - це список розкритих даних для кожного з check_indices

        for i, idx in enumerate(check_indices):
            set_data = factors[i]  # дані для конкретного набору

            # Перевірка кількості кандидатів
            candidates_found = []
            current_id = None

            for item in set_data:
                msg_str = item['msg_str']

                # "ID:Candidate"
                parts = msg_str.split(':')
                if len(parts) != 2:
                    print(f"[ЦВК] ШАХРАЙСТВО: Невірний формат бюлетеня у наборі {idx}")
                    return None

                vid = parts[0]
                cand = parts[1]

                # Перевірка ID (має бути однаковий в межах набору і взагалі)
                if current_id is None:
                    current_id = vid
                elif current_id != vid:
                    print(f"[ЦВК] ШАХРАЙСТВО: Різні ID в одному наборі {idx}")
                    return None

                candidates_found.append(cand)

            # Перевірка складу кандидатів (чи є повний набір варіантів)
            if sorted(candidates_found) != sorted(self.candidates):
                print(f"[ЦВК] ШАХРАЙСТВО: Невірний набір кандидатів у наборі {idx}: {candidates_found}")
                return None

        # 4. Якщо все ОК, підписуємо 10-й набір
        print(f"[ЦВК] Перевірка пройшла успішно. Підписуємо набір №{sign_index}.")

        signed_blinded_ballots = []
        for blinded_val in blinded_sets[sign_index]:
            sig = sign_blinded_message(blinded_val, self.priv_key)
            signed_blinded_ballots.append(sig)

        self.signed_voters.add(voter_name)  # Фіксуємо видачу
        return signed_blinded_ballots

    def receive_vote(self, msg_str, signature):
        # 1. Перевірка підпису ЦВК
        msg_int = string_to_int(msg_str)
        if not verify_signature(msg_int, signature, self.pub_key):
            print(f"[ЦВК] ГОЛОС ВІДХИЛЕНО: Невірний підпис!")
            return

        # 2. Розбір повідомлення
        parts = msg_str.split(':')
        voter_id = parts[0]
        candidate = parts[1]

        # 3. Перевірка на повторне голосування (за ID)
        if voter_id in self.received_ids:
            print(f"[ЦВК] ГОЛОС ВІДХИЛЕНО: ID {voter_id} вже голосував!")
            return

        # 4. Зарахування
        if candidate in self.votes:
            self.votes[candidate] += 1
            self.received_ids.add(voter_id)
            print(f"[ЦВК] Голос за {candidate} зараховано (ID: {voter_id}).")
        else:
            print(f"[ЦВК] ГОЛОС ВІДХИЛЕНО: Невідомий кандидат.")

    def show_results(self):
        print(f"\n--- Результати: {self.votes} ---")
