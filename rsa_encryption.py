from __future__ import annotations

from typing import Generator, Any
import secrets
import sympy
import math

LOG10_2: float = math.log10(2)

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
        self.bit_length: int = modulus.bit_length()
        self.exponent: int = public_exponent

    def __repr__(self) -> str:
        return f'PublicKey({self.modulus}, exponent={self.exponent})'

    def __str__(self) -> str:
        return f'{hex(self.modulus)} (exponent: {self.exponent})'

class PrivateKey:
    def __init__(self, p: int, q: int, public_exponent: int = 65537):
        assert p != q

        self.p: int = p
        self.q: int = q

        self.p_bit_length: int = p.bit_length()
        self.q_bit_length: int = q.bit_length()
        self.bit_length: int = self.p_bit_length + self.q_bit_length

        modulus: int = p * q
        self.totient: int = (p - 1) * (q - 1)

        assert 1 < public_exponent < self.totient
        assert math.gcd(public_exponent, self.totient) == 1
        assert sympy.isprime(p)
        assert sympy.isprime(q)

        self.exponent: int = sympy.mod_inverse(public_exponent, self.totient)
        self.public_key: PublicKey = PublicKey(modulus, public_exponent)

    def __repr__(self) -> str:
        return f'PrivateKey({self.p}, {self.q}, exponent={self.exponent})'

    def __str__(self) -> str:
        return f'{hex(self.p)}, {hex(self.q)} (exponent: {self.exponent})'

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

class CipherText:
    def __init__(self, data: int, bit_length: int):
        self.data: int = data
        self.bit_length: int = bit_length
        self.hex_length: int = math.ceil(self.bit_length / 4)
        self.decimal_length: int = math.ceil(self.bit_length * LOG10_2)

    def __repr__(self) -> str:
        return f'CipherText({self.data}, bit_length={self.bit_length})'

    def __str__(self) -> str:
        return f'0x{hex(self.data)[2:].zfill(self.hex_length)} (length: {self.bit_length} bits)'

def factorize(public_key: PublicKey) -> PrivateKey:
    """
    Performs a factorization to retrieve the private key from a given public key.
    This isn't feasible for modern 2048-bit keys and should only be used on very weak keys.

    :param public_key: The public key to brute force.
    :type public_key: PublicKey
    :return: The associated private key.
    :rtype: PrivateKey
    """
    n: int = public_key.modulus
    factors: Generator[int, Any, None] = sympy.divisors(n, True)

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

def encrypt_int(plaintext: int, key: PublicKey | PrivateKey) -> CipherText:
    """
    Encrypts an integer.
    """
    public_key: PublicKey = key
    if isinstance(key, PrivateKey):
        public_key = key.public_key

    assert plaintext >= 0
    assert plaintext < public_key.modulus

    return CipherText(pow(plaintext, public_key.exponent, public_key.modulus), public_key.bit_length)

def decrypt_int(ciphertext: CipherText, private_key: PrivateKey) -> int:
    """
    Decrypts an integer.
    """
    if isinstance(private_key, PublicKey):
        raise ValueError('Decryption requires a private key, not a public key!')

    return pow(ciphertext.data, private_key.exponent, private_key.public_key.modulus)

def split_bytes_into_blocks(data: bytes, block_size: int) -> Generator[tuple[int, int], None, None]:
    """
    Splits a bytestring into binary blocks of a specified bit length.

    :param data: The bytestring to split.
    :type data: bytes
    :param block_size: The maximum size of each block in bits.
    :type block_size: int
    :return: A generator that yields the block and its size in bits for each block.
    :rtype: Generator[tuple[int, int], None, None]
    """
    assert block_size > 1

    # Initialize
    current_block: int = 1 # Add leading 1 to disambiguate block size
    current_block_size: int = 1

    # Loop through each byte
    for byte in data:
        # Insert byte
        current_block <<= 8
        current_block |= byte
        current_block_size += 8

        # Move to next block if block finished
        while current_block_size >= block_size:
            # Trim excess
            excess_size: int = current_block_size - block_size
            yield current_block >> excess_size, block_size

            # Remove all bits from block except excess, which will be saved for the start of the next block
            current_block &= (1 << excess_size) - 1
            current_block |= (1 << excess_size) # Add leading 1 to disambiguate block size
            current_block_size = excess_size + 1

    if current_block_size > 0:
        yield current_block, current_block_size

def split_ciphertext_into_blocks(ciphertext: CipherText, block_size: int) -> Generator[int, None, None]:
    """
    Splits a ciphertext into binary blocks of a specified bit length.

    :param ciphertext: The ciphertext to split.
    :type ciphertext: CipherText
    :param block_size: The maximum size of each block in bits.
    :type block_size: int
    :return: A generator that yields each block.
    :rtype: Generator[int, None, None]
    """
    assert block_size > 0

    # Initialize
    data: int = ciphertext.data
    block_count: int = math.ceil(ciphertext.bit_length / block_size)
    block_mask: int = (1 << block_size) - 1

    # Split
    for i in range(block_count):
        j: int = block_count - i - 1
        yield (data >> (j * block_size)) & block_mask

def encrypt_bytes(plaintext: bytes, key: PublicKey | PrivateKey, force_block_size: int | None = None) -> CipherText:
    """
    Encrypts a bytestring.

    :param plaintext: The bytestring to encrypt.
    :type plaintext: bytes
    :param key: The public or private key to encrypt the data with.
    :type key: PublicKey | PrivateKey
    :param force_block_size: If not None, forces the encrypter to use this block size in bits.
    :type force_block_size: int | None
    :return: The encrypted bytestring.
    :rtype: CipherText
    """
    # Get public key
    public_key: PublicKey = key
    if isinstance(key, PrivateKey):
        public_key = key.public_key

    # Calculate block size (in bits)
    block_size: int = public_key.bit_length - 1
    if force_block_size is not None:
        assert force_block_size <= block_size
        block_size = force_block_size

    # Encrypt each block
    ciphertext_data: int = 0
    ciphertext_length: int = 0
    blocks: Generator[tuple[int, int], None, None] = split_bytes_into_blocks(plaintext, block_size)
    for block, _ in blocks:
        # Encrypt
        encrypted_block: CipherText = encrypt_int(block, public_key)

        # Insert
        ciphertext_data <<= encrypted_block.bit_length
        ciphertext_data |= encrypted_block.data
        ciphertext_length += encrypted_block.bit_length

    return CipherText(ciphertext_data, ciphertext_length)

def decrypt_bytes(ciphertext: CipherText, private_key: PrivateKey) -> bytes:
    """
    Decrypts a bytestring.

    :param ciphertext: The encrypted data as an int.
    :type ciphertext: CipherText
    :param private_key: The private key to decrypt the data with.
    :type private_key: PrivateKey
    :return: The decrypted bytestring.
    :rtype: bytes
    """
    if isinstance(private_key, PublicKey):
        raise ValueError('Decryption requires a private key, not a public key!')

    # Initialize
    public_key: PublicKey = private_key.public_key
    block_size: int = public_key.bit_length # Encrypted block size is always the same even if the decrypted block size is different

    # Decrypt each block
    plaintext: bytes = b''
    byte_buffer: int = 0
    byte_buffer_size: int = 0
    blocks: Generator[int, None, None] = split_ciphertext_into_blocks(ciphertext, block_size)
    for block in blocks:
        # Decrypt
        decrypted_block: int = decrypt_int(CipherText(block, block_size), private_key)

        # Get block size
        decrypted_block_size: int = decrypted_block.bit_length() - 1

        # Remove the leading 1 that is placed to disambiguate block size
        decrypted_block &= (1 << decrypted_block_size) - 1

        # Add to buffer
        byte_buffer <<= decrypted_block_size
        byte_buffer |= decrypted_block
        byte_buffer_size += decrypted_block_size

        # Empty buffer
        while byte_buffer_size >= 8:
            byte: int = byte_buffer >> (byte_buffer_size - 8) # Grab byte
            plaintext += bytes([byte])
            byte_buffer &= (1 << (byte_buffer_size - 8)) - 1 # Remove byte from buffer
            byte_buffer_size -= 8

    return plaintext

if __name__ == '__main__':
    key: PrivateKey = PrivateKey.random(128)
    print(f'Private key: {key}')
    key: PublicKey = key.public_key
    print(f'Public key: {key}')
    text: bytes = b'Hello, World! This is a test of RSA block-based binary encryption.'
    print(f'Original text: {text}')
    print()
    text: CipherText = encrypt_bytes(text, key)
    print(f'Encrypted: {text}')
    print('Deleted original text and private key.')
    print()
    print('Hacking encryption...')
    key: PrivateKey = factorize(key)
    print(f'Private key found: {key}')
    print()
    text: bytes = decrypt_bytes(text, key)
    print(f'Decrypted: {text}')
    input()
