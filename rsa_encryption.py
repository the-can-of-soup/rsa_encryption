from __future__ import annotations

from typing import Callable
import secrets
import sympy
import math

def random_prime(bits: int = 1024) -> int:
    """
    Generates a random prime number of the specified bit length.
    """
    system_random: secrets.SystemRandom = secrets.SystemRandom()

    while True:
        # Get random number
        p: int = system_random.getrandbits(bits)

        # Ensure proper bit length by forcing binary to begin with 1
        p |= 1 << bits - 1

        # Ensure odd number by forcing binary to end with 1
        p |= 1

        # Check prime
        if sympy.isprime(p):
            return p

class PublicKey:
    def __init__(self, modulus: int, public_exponent: int = 65537):
        self.modulus: int = modulus
        self.exponent: int = public_exponent

    def __repr__(self) -> str:
        return f'PublicKey({self.modulus}, exponent={self.exponent})'

    def __str__(self) -> str:
        return f'{self.modulus} (exponent: {self.exponent})'

class PrivateKey:
    def __init__(self, p: int, q: int, public_exponent: int = 65537):
        self.p: int = p
        self.q: int = q

        modulus: int = p * q
        totient: int = (p - 1) * (q - 1)

        assert 1 < public_exponent < totient
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
        bits //= 2

        return PrivateKey(
            random_prime(bits),
            random_prime(bits),
            public_exponent=public_exponent
        )

    @staticmethod
    def factorize(public_key: PublicKey, progress_update: Callable[[int, int], None] | None = None, update_cooldown: int = 1_000_000) -> PrivateKey:
        """
        Performs a factorization attack to retrieve the private key from a given public key.
        This isn't even remotely feasible for modern 2048-bit keys and should only be used on incredibly weak keys.

        :param public_key: The public key to brute force.
        :type public_key: PublicKey
        :param progress_update: An optional function to be called periodically while cracking. Should be used for progress bars or displays. The function is passed the current number being checked and the maximum number that will be checked.
        :type progress_update: Callable[[int, int], None]
        :param update_cooldown: The number loops to process between each call to ``progress_update``.
        :type update_cooldown: int
        """
        max_p: int = math.ceil(math.sqrt(public_key.modulus))
        assert max_p >= 2

        if progress_update: # Use brute force code that includes update checks only if that feature is being used
            current_update_cooldown: int = update_cooldown - 2
            update_cooldown_expired: bool = False

            for p in range(2, max_p + 1):
                if update_cooldown_expired:
                    progress_update(p, max_p)

                # Check if p is a factor
                if public_key.modulus % p == 0:
                    return PrivateKey(p, public_key.modulus // p, public_key.exponent)

                current_update_cooldown -= 1
                update_cooldown_expired = current_update_cooldown <= 0
                if update_cooldown_expired:
                    current_update_cooldown = update_cooldown

            progress_update(max_p, max_p)

        else: # Use brute force code that does not include update checks if that feature isn't being used
            for p in range(2, max_p + 1):
                # Check if p is a factor
                if public_key.modulus % p == 0:
                    return PrivateKey(p, public_key.modulus // p, public_key.exponent)

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
    ...
    # private_key: PrivateKey = PrivateKey.random()
    # print(f'Random private key: {private_key}')
    # print(f'Associated public key: {private_key.public_key}')
    # print()
    # n: int = 123456
    # print(f'Original: {n}')
    # n = encrypt_int(n, private_key.public_key)
    # print(f'Encrypted: {n}')
    # n = decrypt_int(n, private_key)
    # print(f'Decrypted: {n}')
    # input()
    print(PrivateKey.factorize(PublicKey(1_000_000_000_100_000_000_002_379), progress_update=lambda p, max_p: print(f'{p}/{max_p}', end='\r')))
