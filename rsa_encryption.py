from __future__ import annotations

from typing import Generator
import secrets
import sympy
import math

def random_prime(bits: int = 1024) -> int:
    """
    Generates a random prime number of the specified bit length. Cannot choose 2.
    """
    assert bits >= 2

    system_random: secrets.SystemRandom = secrets.SystemRandom()

    while True:
        # Get random number
        p: int = system_random.getrandbits(bits)

        # Ensure proper bit length and ensure odd number by performing bitwise OR with "10000...00001"
        p |= (1 << bits - 1) | 1

        # Check prime
        if sympy.isprime(p):
            return p

class PublicKey:
    def __init__(self, modulus: int, public_exponent: int = 65537):
        assert modulus > 0
        assert public_exponent > 0

        self.modulus: int = modulus
        self.exponent: int = public_exponent

    def __repr__(self) -> str:
        return f'PublicKey({self.modulus}, exponent={self.exponent})'

    def __str__(self) -> str:
        return f'{self.modulus} (exponent: {self.exponent})'

class PrivateKey:
    def __init__(self, p: int, q: int, public_exponent: int = 65537):
        assert p != q

        self.p: int = p
        self.q: int = q

        modulus: int = p * q
        totient: int = (p - 1) * (q - 1)

        assert 1 < public_exponent < totient
        assert math.gcd(public_exponent, totient) == 1
        assert sympy.isprime(p)
        assert sympy.isprime(q)

        self.exponent: int = sympy.mod_inverse(public_exponent, totient)
        self.public_key: PublicKey = PublicKey(modulus, public_exponent)

    def __repr__(self) -> str:
        return f'PrivateKey({self.p}, {self.q}, exponent={self.exponent})'

    def __str__(self) -> str:
        return f'{self.p}, {self.q} (exponent: {self.exponent})'

    @staticmethod
    def random(bits: int = 2048, public_exponent: int = 65537) -> PrivateKey:
        """
        Generates a random private key of the specified bit length.
        """
        assert bits % 2 == 0
        assert bits >= 6 # 3 bits for each factor, which barely allows for 2 different primes (5 or 101 and 7 or 111)
        bits //= 2

        p: int = random_prime(bits)
        q: int = random_prime(bits)
        while p == q:
            q = random_prime(bits)

        return PrivateKey(p, q, public_exponent=public_exponent)

def factorize(public_key: PublicKey) -> PrivateKey:
    """
    Performs a factorization to retrieve the private key from a given public key.
    This isn't feasible for modern 2048-bit keys and should only be used on very weak keys.

    :param public_key: The public key to brute force.
    :type public_key: PublicKey
    """
    n: int = public_key.modulus
    factors: Generator[int, None, None] = sympy.divisors(n, True)

    p: int = 1
    while p == 1 or p == n:
        try:
            p = next(factors)
        except StopIteration:
            break
    else: # Runs when while loop exits normally
        q = n // p
        return PrivateKey(p, q, public_exponent=public_key.exponent)

    raise ValueError('Something went horribly wrong and not a single valid private key was found.')

def encrypt_int(plaintext: int, public_key: PublicKey):
    """
    Encrypts an integer.
    """
    return pow(plaintext, public_key.exponent, public_key.modulus)

def decrypt_int(ciphertext: int, private_key: PrivateKey):
    """
    Decrypts an integer.
    """
    return pow(ciphertext, private_key.exponent, private_key.public_key.modulus)

if __name__ == '__main__':
    print(factorize(PublicKey(1_000_000_000_100_000_000_002_379)))
