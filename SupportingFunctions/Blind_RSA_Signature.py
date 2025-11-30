import random
from SupportingFunctions.RSA_functions import gcd, modinv


# Сліпий підпис RSA
def blind_message(message_int, pub_key):
    # m' = (m * r^e) mod n
    e, n = pub_key
    while True:
        r = random.randint(2, n - 1)
        if gcd(r, n) == 1:
            break
    blinded_m = (message_int * pow(r, e, n)) % n
    return blinded_m, r


def sign_blinded_message(blinded_m, priv_key):
    # s' = (m')^d mod n
    d, n = priv_key
    return pow(blinded_m, d, n)


def unblind_signature(signed_blinded, r, pub_key):
    # s = s' * r^(-1) mod n
    e, n = pub_key
    r_inv = modinv(r, n)
    return (signed_blinded * r_inv) % n
