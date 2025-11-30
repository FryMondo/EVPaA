from SupportingFunctions.RSA_functions import *


# --- Реалізація хешування ---
def custom_hash(message, n):
    # H_i = (H_{i-1} + M_i)^2 mod n
    h = 0
    for char in message:
        m_i = ord(char)
        h = ((h + m_i) ** 2) % n
    return h


def encrypt_rsa(message_str, public_key):
    # c = m^e mod n
    e, n = public_key
    cipher = []
    for char in message_str:
        m = ord(char)
        c = pow(m, e, n)
        cipher.append(c)
    return cipher


def decrypt_rsa(cipher_list, private_key):
    # m = c^d mod n
    d, n = private_key
    message_chars = []
    for c in cipher_list:
        m = pow(c, d, n)
        message_chars.append(chr(m))
    return "".join(message_chars)


def sign_message(message, private_key):
    # S = H^d mod n
    d, n = private_key
    h = custom_hash(message, n)
    signature = pow(h, d, n)
    return signature


def verify_signature(message, signature, public_key):
    # H_c = S^e mod n
    e, n = public_key
    h_original = custom_hash(message, n)
    h_check = pow(signature, e, n)
    return h_original == h_check


# --- Класи Протоколу ---
class Voter:
    def __init__(self, name):
        self.name = name
        self.public_key, self.private_key = generate_keypair(50, 200)
        self.voted = False

    def prepare_vote(self, candidate_name, cec_public_key):
        signature = sign_message(candidate_name, self.private_key)

        ballot_content = f"{candidate_name}||{signature}||{self.name}"

        encrypted_ballot = encrypt_rsa(ballot_content, cec_public_key)
        return encrypted_ballot


class CEC:
    def __init__(self, candidates):
        self.public_key, self.private_key = generate_keypair(50, 200)
        self.candidates = {cand: 0 for cand in candidates}
        self.voters_registry = {}  # {name: public_key}
        self.processed_voters = set()

    def register_voter(self, voter):
        self.voters_registry[voter.name] = voter.public_key
        print(f"[ЦВК] Виборець {voter.name} зареєстрований.")

    def process_vote(self, encrypted_ballot):
        try:
            decrypted_text = decrypt_rsa(encrypted_ballot, self.private_key)

            parts = decrypted_text.split('||')
            if len(parts) != 3:
                print(f"[ЦВК] ПОМИЛКА: Невірний формат бюлетеня.")
                return False

            candidate_choice = parts[0]
            signature = int(parts[1])
            voter_name = parts[2]

            if voter_name not in self.voters_registry:
                print(f"[ЦВК] ВІДХИЛЕНО: Виборець '{voter_name}' не знайдений у списку.")
                return False

            if voter_name in self.processed_voters:
                print(f"[ЦВК] ВІДХИЛЕНО: Виборець '{voter_name}' вже голосував. Голос проігноровано.")
                return False

            voter_pub_key = self.voters_registry[voter_name]
            is_valid = verify_signature(candidate_choice, signature, voter_pub_key)

            if not is_valid:
                print(f"[ЦВК] ВІДХИЛЕНО: Підпис виборця '{voter_name}' недійсний або дані пошкоджені.")
                return False

            if candidate_choice in self.candidates:
                self.candidates[candidate_choice] += 1
                self.processed_voters.add(voter_name)
                print(f"[ЦВК] Голос від '{voter_name}' за '{candidate_choice}' ЗАРАХОВАНО.")
                return True
            else:
                print(f"[ЦВК] ВІДХИЛЕНО: Кандидат '{candidate_choice}' не існує.")
                return False

        except Exception as e:
            print(f"[ЦВК] КРИТИЧНА ПОМИЛКА обробки: {e}")
            return False

    def show_results(self):
        print("\n--- РЕЗУЛЬТАТИ ГОЛОСУВАННЯ ---")
        max_votes = -1
        winners = []
        for cand, votes in self.candidates.items():
            print(f"{cand}: {votes}")
            if votes > max_votes:
                max_votes = votes
                winners = [cand]
            elif votes == max_votes:
                winners.append(cand)

        print("-" * 30)
        if len(winners) > 1:
            print(f"УВАГА: Нічия між {', '.join(winners)}. Потреба в повторному голосуванні.")
        else:
            print(f"Переможець: {winners[0]}")
