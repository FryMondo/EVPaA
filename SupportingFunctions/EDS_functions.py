import hashlib


# ЕЦП (Хешування + RSA)
def sign_hash(message, private_key):
    # Підпис хешу повідомлення
    d, n = private_key
    msg_hash = int(hashlib.sha256(message.encode()).hexdigest(), 16) % n
    signature = pow(msg_hash, d, n)
    return signature


def verify_signature(message, signature, public_key):
    e, n = public_key
    msg_hash = int(hashlib.sha256(message.encode()).hexdigest(), 16) % n
    check = pow(signature, e, n)
    return check == msg_hash
