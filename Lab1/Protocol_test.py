from SimpleProtocol import *

print("ЕТАП 1: Налаштування")
candidates_list = ["Candidate A", "Candidate B"]
cec = CEC(candidates_list)

voters = [Voter(f"Voter_{i}") for i in range(1, 6)]

for v in voters[:4]:
    cec.register_voter(v)

print("\nЕТАП 2: Процес голосування та Тестування")

print("Voter_1 голосує за Candidate A")
ballot_1 = voters[0].prepare_vote("Candidate A", cec.public_key)
cec.process_vote(ballot_1)

print("\nVoter_2 голосує за Candidate B")
ballot_2 = voters[1].prepare_vote("Candidate B", cec.public_key)
cec.process_vote(ballot_2)

print("\nVoter_1 намагається проголосувати знову (Повторне отримання бюлетеня)")
cec.process_vote(ballot_1)

print("\nНезареєстрований Voter_5 намагається проголосувати")
ballot_unreg = voters[4].prepare_vote("Candidate A", cec.public_key)
cec.process_vote(ballot_unreg)

print("\nСпроба відправки пошкодженого бюлетеня (від Voter_3)")
ballot_3 = voters[2].prepare_vote("Candidate B", cec.public_key)
tampered_ballot = list(ballot_3)
tampered_ballot[-1] = (tampered_ballot[-1] + 1) % cec.public_key[1]
cec.process_vote(tampered_ballot)

print("\nVoter_3 переголосовує нормально за Candidate B")
cec.process_vote(ballot_3)

print("\nVoter_4 голосує за Candidate A")
ballot_4 = voters[3].prepare_vote("Candidate A", cec.public_key)
cec.process_vote(ballot_4)

cec.show_results()
