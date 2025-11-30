from SupportingFunctions.RSA_functions import is_prime
from SupportingFunctions.Blind_RSA_Signature import *


def generate_keypair():
    # Для демо генеруємо невеликі ключі для швидкості
    start, end = 100, 500
    primes = [i for i in range(start, end) if is_prime(i)]
    p = random.choice(primes)
    q = random.choice(primes)
    while p == q:
        q = random.choice(primes)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while gcd(e, phi) != 1:
        e = random.randrange(3, phi, 2)
    d = modinv(e, phi)
    return (e, n), (d, n)


def verify_signature(message_int, signature, pub_key):
    # s^e mod n == m
    e, n = pub_key
    return pow(signature, e, n) == message_int


# Розподіл секрету (ID) на 2 частини
def split_secret(secret_id):
    # ID = part1 * part2
    # Беремо part1 випадково, part2 обчислюємо
    # Шифруємо частини для MLC. MLC розшифрує й об'єднає
    part1 = random.randint(1, secret_id - 1)
    part2 = secret_id - part1
    return part1, part2


# Шифрування (звичайне RSA)
def encrypt(m, pub_key):
    e, n = pub_key
    return pow(m, e, n)


def decrypt(c, priv_key):
    d, n = priv_key
    return pow(c, d, n)


# --- 1. Центральна Виборча Комісія ---
class CEC:
    def __init__(self, candidates):
        self.pub, self.priv = generate_keypair()
        self.candidates = candidates
        self.registered_tokens = set()  # Токени, які отримали сліпий підпис
        self.final_votes = {name: 0 for name in candidates.values()}
        self.voter_table = []  # ID -> Decrypted Ballot

    def blind_sign_request(self, blinded_token):
        # ЦВК підписує право на голос (сліпий підпис)
        return sign_blinded_message(blinded_token, self.priv)

    def receive_results(self, mlc_results):
        print("\n[ЦВК] Отримання даних від ВК Середнього Рівня...")
        for record in mlc_results:
            v_token = record['token']
            vote_val = record['vote_value']

            # Додаємо в таблицю публікації
            cand_name = self.candidates.get(vote_val, "INVALID")
            self.voter_table.append(f"Token: {v_token} -> Vote: {vote_val} ({cand_name})")

            if cand_name != "INVALID":
                self.final_votes[cand_name] += 1

    def publish_results(self):
        print("\n" + "=" * 30)
        print("РЕЗУЛЬТАТИ ГОЛОСУВАННЯ (ЦВК)")
        print("=" * 30)
        for cand, count in self.final_votes.items():
            print(f"{cand}: {count}")
        print("-" * 30)
        print("Таблиця перевірки (Token -> Vote):")
        for row in self.voter_table:
            print(row)

# --- 2. ВК Середнього Рівня ---
class MLC:
    def __init__(self, name, cec_pub):
        self.name = name
        self.pub, self.priv = generate_keypair()
        self.cec_pub = cec_pub
        # Зберігання частин: {token: {1: part1, 2: part2}}
        self.parts_storage = {}
        self.processed_tokens = set()

    def collect_data(self, llc_data, part_num):
        # llc_data - список пакетів від ВК низького рівня
        # part_num - номер частини бюлетеня (1 або 2)
        print(f"[{self.name}] Отримано пачку даних (Частина {part_num})")

        for packet in llc_data:
            token = packet['token']
            signature = packet['signature']
            enc_part = packet['enc_part']

            # Перевірка: чи має цей токен право голосу (перевірка сліпого підпису ЦВК)
            if not verify_signature(token, signature, self.cec_pub):
                print(f"   -> [УВАГА] Невалідний підпис токена {token}! Ігноруємо.")
                continue

            if token not in self.parts_storage:
                self.parts_storage[token] = {}

            self.parts_storage[token][part_num] = enc_part

    def process_votes(self):
        # Об'єднання, розшифрування, підрахунок
        results = []
        print(f"[{self.name}] Обробка та відновлення бюлетенів...")

        for token, parts in self.parts_storage.items():
            if 1 in parts and 2 in parts:
                # Є обидві частини
                c1 = parts[1]
                c2 = parts[2]

                # Розшифровуємо
                p1 = decrypt(c1, self.priv)
                p2 = decrypt(c2, self.priv)

                # Відновлюємо (Адитивна схема: Vote = p1 + p2)
                recovered_vote = p1 + p2

                results.append({'token': token, 'vote_value': recovered_vote})
                self.processed_tokens.add(token)
            else:
                print(f"   -> Токен {token}: Неповний комплект частин. Відхилено.")

        return results

# --- 3. ВК Низького Рівня ---
class LLC:
    def __init__(self, name, parent_mlc):
        self.name = name
        self.parent_mlc = parent_mlc
        self.buffer = []  # Тимчасове сховище {token, signature, enc_part}

    def receive_ballot_part(self, token, signature, enc_part):
        # ВК низького рівня збирає частини
        self.buffer.append({
            'token': token,
            'signature': signature,
            'enc_part': enc_part
        })

    def push_to_mlc(self, part_num):
        # Передача даних нагору
        print(f"[{self.name}] Передача {len(self.buffer)} частин до {self.parent_mlc.name}...")
        self.parent_mlc.collect_data(self.buffer, part_num)
        self.buffer = []  # Очистка


class Voter:
    def __init__(self, name):
        self.name = name
        self.token = random.randint(10000, 99999)  # Випадковий ID токен
        self.signed_token = None  # Право на голос

    def register(self, cec):
        # Сліпий підпис
        blinded, r = blind_message(self.token, cec.pub)
        # Відправка у ЦВК (ЦВК не бачить токен)
        blind_sig = cec.blind_sign_request(blinded)
        # Зняття маскування
        self.signed_token = unblind_signature(blind_sig, r, cec.pub)
        # Перевірка
        if verify_signature(self.token, self.signed_token, cec.pub):
            print(f"[{self.name}] Отримано право голосу (Сліпий підпис).")
        else:
            print(f"[{self.name}] Помилка верифікації підпису!")

    def vote(self, candidate_id, llc1, llc2, mlc_pub):
        # llc1 і llc2 - це комісії, прикріплені до одного MLC
        if not self.signed_token:
            print(f"[{self.name}] Немає права голосу!")
            return

        # 1. Розділення голосу
        p1, p2 = split_secret(candidate_id)

        # 2. Шифрування частин ключем MLC (щоб LLC не бачили зміст)
        enc_p1 = encrypt(p1, mlc_pub)
        enc_p2 = encrypt(p2, mlc_pub)

        # 3. Відправка
        # Частина 1 -> LLC 1
        llc1.receive_ballot_part(self.token, self.signed_token, enc_p1)
        # Частина 2 -> LLC 2
        llc2.receive_ballot_part(self.token, self.signed_token, enc_p2)

        print(f"[{self.name}] Голос відправлено: Частини розкидано по {llc1.name} та {llc2.name}.")
