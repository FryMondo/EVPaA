from SupportingFunctions.RSA_functions import *
from SupportingFunctions.EDS_functions import *


def encrypt_rsa(message_int_list, public_key):
    e, n = public_key
    return [pow(m, e, n) for m in message_int_list]


def decrypt_rsa(cipher_list, private_key):
    d, n = private_key
    return [pow(c, d, n) for c in cipher_list]


def str_to_int_list(s):
    return [ord(c) for c in s]


def int_list_to_str(l):
    return "".join(chr(i) for i in l)


# --- Учасники Протоколу ---

class RegistrationBureau:
    def __init__(self):
        self.issued_rns = {}  # {VoterName: RN} - приватна база
        self.valid_rns_list = set()  # Список для передачі у ВК

    def register_voter(self, voter_name):
        # Перевірка на повторну реєстрацію
        if voter_name in self.issued_rns:
            print(f"[БР] ВІДМОВА: Виборець {voter_name} вже має RN.")
            return None

        # Генерація унікального RN
        rn = random.randint(10000, 99999)
        while rn in self.valid_rns_list:
            rn = random.randint(10000, 99999)

        self.issued_rns[voter_name] = rn
        self.valid_rns_list.add(rn)
        print(f"[БР] Видано RN для {voter_name}.")
        return rn

    def get_rn_list_for_ec(self):
        # БР відправляє список RN до ВК без імен
        return list(self.valid_rns_list)


class ElectionCommission:
    def __init__(self, candidates):
        self.public_key, self.private_key = generate_keypair(100, 300)
        self.candidates = candidates
        self.valid_rns = set()
        self.used_rns = set()
        self.votes_db = []  # Список: {id, vote, signature}

    def load_rn_list(self, rn_list):
        self.valid_rns = set(rn_list)
        print(f"[ВК] Завантажено {len(rn_list)} валідних RN від БР.")

    def receive_packet(self, encrypted_packet):
        try:
            # 1. Розшифрування
            decrypted_ints = decrypt_rsa(encrypted_packet, self.private_key)
            decrypted_str = int_list_to_str(decrypted_ints)

            # Очікуваний формат: "RN||ID||Vote||Signature||e_voter||n_voter"
            # Виборець передає свій публічний ключ, щоб ВК могла перевірити підпис, не знаючи імені
            parts = decrypted_str.split('||')
            if len(parts) != 6:
                return "INVALID_FORMAT"

            rn = int(parts[0])
            v_id = parts[1]
            vote = parts[2]
            signature = int(parts[3])
            voter_pub_key = (int(parts[4]), int(parts[5]))

            # 2. Перевірка RN
            if rn not in self.valid_rns:
                print(f"[ВК] ВІДХИЛЕНО: Невалідний RN ({rn}).")
                return "INVALID_RN"

            if rn in self.used_rns:
                print(f"[ВК] ВІДХИЛЕНО: RN ({rn}) вже використано!")
                return "DOUBLE_VOTE_RN"

            # 3. Перевірка підпису
            if not verify_signature(vote, signature, voter_pub_key):
                print(f"[ВК] ВІДХИЛЕНО: Невірний цифровий підпис.")
                return "INVALID_SIG"

            # 4. Зарахування
            if vote in self.candidates:
                self.used_rns.add(rn)  # Викреслюємо RN
                self.votes_db.append({'id': v_id, 'vote': vote, 'sig': signature})
                print(f"[ВК] Голос прийнято (ID: {v_id}).")
                return "OK"
            else:
                print(f"[ВК] ВІДХИЛЕНО: Кандидат не існує.")
                return "INVALID_CANDIDATE"

        except Exception as e:
            print(f"[ВК] Помилка обробки: {e}")
            return "ERROR"

    def publish_results(self):
        # Публікація ID та бюлетенів
        return self.votes_db


class Voter:
    def __init__(self, name):
        self.name = name
        self.public_key, self.private_key = generate_keypair(100, 300)
        self.rn = None
        self.id = None
        self.my_vote = None

    def get_registered(self, bureau):
        self.rn = bureau.register_voter(self.name)

    def vote(self, candidate, ec_pub_key, ec, manual_rn=None, manual_id=None):
        # Генерація ID
        vote_id = str(random.randint(100000, 999999)) if not manual_id else manual_id
        rn_to_use = self.rn if manual_rn is None else manual_rn

        if rn_to_use is None:
            print(f"{self.name} не має RN!")
            return None

        # Збереження для себе (для перевірки пізніше)
        self.id = vote_id
        self.my_vote = candidate

        # Формування бюлетеня та підпис
        signature = sign_hash(candidate, self.private_key)

        # Пакет: RN||ID||Vote||Signature||MyPubKey
        packet_str = f"{rn_to_use}||{vote_id}||{candidate}||{signature}||{self.public_key[0]}||{self.public_key[1]}"

        # Шифрування ключем ВК
        encrypted_packet = encrypt_rsa(str_to_int_list(packet_str), ec_pub_key)

        # Відправка
        return ec.receive_packet(encrypted_packet)

    def verify_my_vote(self, published_list):
        #  Перевірка, чи є мій ID і, чи вірний голос
        found = False
        for record in published_list:
            if record['id'] == self.id:
                found = True
                if record['vote'] == self.my_vote:
                    print(
                        f"[Перевірка {self.name}] УСПІХ: Мій голос '{self.my_vote}' враховано вірно під ID {self.id}.")
                else:
                    print(
                        f"[Перевірка {self.name}] ТРИВОГА! Мій ID знайдено, але голос підроблено! "
                        f"(Там: {record['vote']}, Моє: {self.my_vote})")

        if not found:
            print(f"[Перевірка {self.name}] ТРИВОГА! Мій ID {self.id} не знайдено у списках!")
