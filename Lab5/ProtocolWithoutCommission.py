import hashlib
import random
from SupportingFunctions.RSA_functions import gcd, modinv, is_prime


def generate_keypair():
    start, end = 500, 2000

    primes = [i for i in range(start, end) if is_prime(i)]
    if len(primes) < 2:
        raise Exception("Замалий діапазон простих чисел")

    p = random.choice(primes)
    q = random.choice(primes)
    while p == q:
        q = random.choice(primes)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    # Якщо e не взаємно просте з phi (рідко, але буває), перегенеруємо
    while gcd(e, phi) != 1:
        p = random.choice(primes)
        q = random.choice(primes)
        n = p * q
        phi = (p - 1) * (q - 1)

    d = modinv(e, phi)
    return (e, n), (d, n)


def encrypt_rsa(message_str, public_key):
    # Розбиває повідомлення на блоки та шифрує кожен окремо
    e, n = public_key
    msg_bytes = message_str.encode('utf-8')

    # Максимальний розмір блоку в байта має бути меншим за n
    key_size_bytes = (n.bit_length() + 7) // 8
    block_size = key_size_bytes - 1
    if block_size < 1: block_size = 1

    encrypted_blocks = []

    # Проходимо по байтах повідомлення шматками
    for i in range(0, len(msg_bytes), block_size):
        chunk = msg_bytes[i:i + block_size]
        m_int = int.from_bytes(chunk, 'big')
        c = pow(m_int, e, n)
        encrypted_blocks.append(str(c))

    return ".".join(encrypted_blocks)


def decrypt_rsa(cipher_str, private_key):
    # Розбиває рядок по крапках, дешифрує блоки та склеює байти.
    d, n = private_key
    try:
        blocks = cipher_str.split('.')
        decrypted_bytes = b""

        for b_str in blocks:
            c = int(b_str)
            m_int = pow(c, d, n)

            # Конвертуємо число назад у байти
            length = (m_int.bit_length() + 7) // 8
            decrypted_bytes += m_int.to_bytes(length, 'big')

        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        # Якщо розшифрування не вдалося (наприклад, через підміну шифротексту)
        return "GARBAGE"


# --- 1. ЕЦП (Підпис пакета) ---
def sign_batch(batch_data, private_key):
    # s = m^d mod n (тут d це key[0] у (d,n))
    # Хешуємо строкове представлення пакету
    data_str = str(batch_data)
    # Хеш обрізаємо по модулю n, щоб підписати
    h = int(hashlib.sha256(data_str.encode()).hexdigest(), 16) % private_key[1]
    return pow(h, private_key[0], private_key[1])


def verify_batch_signature(batch_data, signature, public_key):
    # h = s^e mod n
    data_str = str(batch_data)
    h_calc = int(hashlib.sha256(data_str.encode()).hexdigest(), 16) % public_key[1]
    h_dec = pow(signature, public_key[0], public_key[1])
    return h_calc == h_dec


# --- 2. Логіка Виборця ---
class Voter:
    def __init__(self, name):
        self.name = name
        self.pub, self.priv = generate_keypair()
        self.my_rps = {}  # Збережені випадкові рядки (RP) для кожного шару

    def create_onion_ballot(self, vote, ordered_participants):
        # Створення багатошарового бюлетеня (Onion)
        # ordered_participants: список учасників у порядку розшифрування (A -> B -> ... -> E)
        payload = vote

        # Шифруємо у зворотному порядку: спочатку для останнього (E),
        # потім результат для передостаннього і т.д., щоб A був зверху
        for participant in reversed(ordered_participants):
            # Генеруємо унікальний RP для цього шару
            rp = f"RP:{self.name}->{participant.name}:{random.randint(1000, 9999)}"
            self.my_rps[participant.name] = rp

            # Додаємо RP до корисного навантаження
            data_to_encrypt = f"{payload}||{rp}"

            # Шифруємо і результат стає payload для наступного (зовнішнього) шару
            payload = encrypt_rsa(data_to_encrypt, participant.pub)

        return payload

    def process_batch(self, batch_obj, sender_pub_key=None):
        # Обробка пакета бюлетенів
        # 1. Перевірка підпису
        if sender_pub_key:
            if not verify_batch_signature(batch_obj['ballots'], batch_obj['signature'], sender_pub_key):
                print(f"[{self.name}] КРИТИЧНА ПОМИЛКА: Невірний підпис пакету!")
                return None

        input_ballots = batch_obj['ballots']
        decrypted_ballots = []
        found_my_ballot = False

        print(f"[{self.name}] Обробка {len(input_ballots)} бюлетенів...")

        # Перевірка на кількість
        expected_count = 5  # У нашому сценарії ми знаємо, що 5 учасників
        if len(input_ballots) != expected_count:
            print(
                f"   >>> [ТРИВОГА] Кількість бюлетенів змінилася! Очікувалось {expected_count}, "
                f"отримано {len(input_ballots)}.")

        # 2. Розшифрування
        for cipher_str in input_ballots:
            plain = decrypt_rsa(cipher_str, self.priv)

            if plain == "GARBAGE":
                print(f"   >>> [ПОМИЛКА] Бюлетень пошкоджено (не вдалося розшифрувати).")
                decrypted_ballots.append("CORRUPTED")
                continue

            # Розбір формату "NextPayload||RP"
            if "||" not in plain:
                # Це може бути фінальний голос на останньому кроці
                # Або якщо структура порушена
                decrypted_ballots.append(plain)
                # Якщо це останній крок, RP вже може не бути, або він всередині
            else:
                parts = plain.split('||')
                next_payload = parts[0]
                rp = parts[1]

                # 3. Перевірка RP
                if self.my_rps.get(self.name) == rp:
                    found_my_ballot = True

                decrypted_ballots.append(next_payload)

        if not found_my_ballot:
            print(f"   >>> [ТРИВОГА] Я не знайшов свій бюлетень (RP не знайдено)!")
        else:
            print(f"   [OK] Мій бюлетень на місці.")

        # 4. Перемішування
        random.shuffle(decrypted_ballots)

        # 5. Підпис
        sig = sign_batch(decrypted_ballots, self.priv)

        return {'ballots': decrypted_ballots, 'signature': sig}
