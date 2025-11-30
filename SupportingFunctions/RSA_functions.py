import random


# КРИПТОГРАФІЧНЕ ЯДРО RSA
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extended_gcd(b % a, a)
        return g, x - (b // a) * y, y


def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Модульне обернене число не існує')
    else:
        return x % m


def is_prime(num):
    if num < 2: return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0: return False
    return True


def generate_keypair(num1, num2):
    primes = [i for i in range(num1, num2) if is_prime(i)]
    p = random.choice(primes)
    primes.remove(p)
    q = random.choice(primes)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    d = modinv(e, phi)
    return (e, n), (d, n)
