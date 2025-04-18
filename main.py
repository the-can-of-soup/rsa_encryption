# GitHub: https://github.com/the-can-of-soup/rsa_encryption

import rsa_encryption as rsa
import soup_tui as tui
import soup_tui.keyboard as kb
import traceback
import random
import pickle
import time
import os

# All "PurpleMind"-related things refer to this YouTube video: https://www.youtube.com/watch?v=EY6scAHNgZw
# The online encrypter PurpleMind provides is here: https://www.purplemindcreations.com/rsa-encryption-helper
# The explanation of their encrypter is here: https://www.purplemindcreations.com/explanation

# noinspection SpellCheckingInspection
PURPLEMIND_ENGLISH_WORDS: list[str] = [
    'apple', 'banana', 'cherry', 'dog', 'elephant', 'fish', 'grape', 'hat', 'ink', 'jump',
    'kangaroo', 'lion', 'monkey', 'net', 'orange', 'peach', 'quilt', 'rose', 'sun', 'tree',
    'umbrella', 'vulture', 'whale', 'xenon', 'yellow', 'zebra'
]
# noinspection SpellCheckingInspection
PURPLEMIND_PUBLIC_KEY_STR: str = f'\n\nPublic Key used on the website:\n0xd3c21bcf27e0b17a494b\n1000000000100000000002379\ne = 65537'
# noinspection SpellCheckingInspection
PURPLEMIND_PRIVATE_KEY_STR: str = f'\n\nPrivate Key used on the website:\n0xe8d4a51027,0xe8d4a5103d\n1000000000039,1000000000061\ne = 65537'
DIGITS: list[str] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

def print_title() -> None:
    tui.clear_screen()
    tui.praw(f'{tui.ANSI.BRIGHT_GREEN + tui.ANSI.INVERT}RSA ENCRYPTION{tui.ANSI.RESET + tui.ANSI.BRIGHT_GREEN}\n\n')

def private_key_from_text(text: str, public_exponent: int = 65537) -> rsa.PrivateKey:
    p: str
    q: str
    p, q = text.split(',')

    p: int = int(p, 16 if p.startswith('0x') else 10)
    q: int = int(q, 16 if q.startswith('0x') else 10)

    return rsa.PrivateKey(p, q, public_exponent=public_exponent)

# noinspection PyShadowingNames
def private_key_input() -> rsa.PrivateKey:
    tui.praw('Private keys should be two numbers separated by a comma.\nIf using hexadecimal, each number should start with "0x".\n\nEnter private key: ')
    factors: str = tui.iraw()
    tui.praw('Enter public exponent: ')
    exponent: int = int(tui.iraw())
    return private_key_from_text(factors, public_exponent=exponent)

# noinspection PyShadowingNames
def public_key_input(accept_private_keys: bool = True) -> rsa.PublicKey:
    tui.praw('If using hexadecimal, add "0x" to the beginning of the key.')
    if accept_private_keys:
        tui.praw('\nPrivate keys are also accepted.\n\nEnter public/private key: ')
    else:
        tui.praw('\n\nEnter public key: ')
    modulus: str = tui.iraw()
    tui.praw('Enter public exponent: ')
    exponent: int = int(tui.iraw())

    if ',' in modulus and accept_private_keys: # User gave a private key
        private_key: rsa.PrivateKey = private_key_from_text(modulus, public_exponent=exponent)
        return private_key.public_key

    modulus: int = int(modulus, 16 if modulus.startswith('0x') else 10)
    return rsa.PublicKey(modulus, public_exponent=exponent)

# noinspection PyShadowingNames
def print_private_key(key: rsa.PrivateKey, verbose: bool = False) -> None:
    tui.praw(f'\nPRIVATE KEY\n\n')
    if verbose:
        tui.praw(f'Length: {key.p_bit_length} + {key.q_bit_length} = {key.bit_length} bits\n\n')
    tui.praw(f'Hexadecimal\n{hex(key.p)},{hex(key.q)}\n\nDecimal\n{key.p},{key.q}\n\n')
    if verbose:
        tui.praw(f'd = {key.exponent}\nφ(n) = {key.totient}\n\n')
    tui.praw(f'PUBLIC KEY\n\n')
    if verbose:
        tui.praw(f'Length: {key.public_key.bit_length} bits\n\n')
    tui.praw(f'Hexadecimal\n{hex(key.public_key.modulus)}\n\nDecimal\n{key.public_key.modulus}\n\ne = {key.public_key.exponent}\n\n')

# noinspection PyShadowingNames, SpellCheckingInspection
def purplemind_text_to_int(plaintext: str) -> int:
    plaintext: bytes = plaintext.encode('ansi')
    plaintext_int: int = 0

    for byte in plaintext:
        plaintext_int *= 1000
        plaintext_int += byte

    return plaintext_int

# noinspection PyShadowingNames, SpellCheckingInspection
def purplemind_int_to_text(plaintext_int: int) -> str:
    plaintext: bytes = b''

    while plaintext_int > 0:
        plaintext = bytes([plaintext_int % 1000]) + plaintext
        plaintext_int //= 1000

    plaintext: str = plaintext.decode('ansi')
    return plaintext

# noinspection PyShadowingNames, SpellCheckingInspection
def encrypt_purplemind(plaintext: str, key: rsa.PublicKey) -> str:
    # Save first 30 characters because they are not encrypted
    first_30_chars: str = plaintext[:30]
    plaintext = plaintext[30:]

    # Split remaining characters into 8 character chunks
    chunks: list[str] = []
    while len(plaintext) > 0:
        chunks.append(plaintext[:8])
        plaintext = plaintext[8:]

    # Encrypt each chunk
    encrypted_chunks: list[rsa.CipherText] = []
    for chunk in chunks:
        chunk_int: int = purplemind_text_to_int(chunk)
        encrypted_chunks.append(rsa.encrypt_int(chunk_int, key))

    # Concatenate chunks with a size of 24 digits per chunk
    ciphertext: str = ''
    for encrypted_chunk in encrypted_chunks:
        ciphertext += str(encrypted_chunk.data).zfill(24)

    # Insert random words and add back first 30 characters
    ciphertext_with_words: str = first_30_chars
    i = 0
    while i < len(ciphertext):
        ciphertext_with_words += f'{ciphertext[i:i + 3]} {random.choice(PURPLEMIND_ENGLISH_WORDS)} '
        i += 3
    ciphertext_with_words = ciphertext_with_words[:-1]

    return ciphertext_with_words

# noinspection PyShadowingNames, SpellCheckingInspection
def decrypt_purplemind(ciphertext: str, key: rsa.PrivateKey) -> str:
    # Save first 30 characters because they are not encrypted
    first_30_chars: str = ciphertext[:30]
    ciphertext = ciphertext[30:]

    # Remove random words
    ciphertext_no_words: str = ''
    for c in ciphertext:
        if c in DIGITS:
            ciphertext_no_words += c
    ciphertext = ciphertext_no_words

    # Split remaining characters into 24 character encrypted chunks
    encrypted_chunks: list[int] = []
    while len(ciphertext) > 0:
        encrypted_chunks.append(int(ciphertext[:24]))
        ciphertext = ciphertext[24:]

    # Decrypt each chunk
    chunks: list[str] = []
    for encrypted_chunk in encrypted_chunks:
        chunk_int: int = rsa.decrypt_int(rsa.CipherText(encrypted_chunk, 24), key)
        chunks.append(purplemind_int_to_text(chunk_int))

    # Join chunks and add back first 30 characters
    plaintext: str = first_30_chars
    for chunk in chunks:
        plaintext += chunk

    return plaintext

if __name__ == '__main__':
    if not os.path.isdir('output'):
        os.mkdir('output')
    if not os.path.isdir('input'):
        os.mkdir('input')

    while True:
        print_title()
        tui.praw('[E] Encrypt\n')
        tui.praw('[D] Decrypt\n')
        tui.praw('[F] Factorization Attack\n')
        tui.praw('[G] Generate Key\n')
        tui.praw('[K] Process Key\n')
        tui.praw('[Q] Quit\n\n')
        action: str = kb.read_key()

        try:
            if action == 'q':
                break

            elif action == 'g':
                print_title()
                tui.praw('GENERATE RANDOM KEY\n\n')
                tui.praw('Enter the length in bits: ')
                bits: int = int(tui.iraw())
                tui.praw('Enter the public exponent: ')
                exponent: int = int(tui.iraw())
                tui.praw('\nGenerating key...\n')

                start_time: float = time.time()
                key: rsa.PrivateKey = rsa.PrivateKey.random(bits, public_exponent=exponent)
                end_time: float = time.time()
                elapsed_time: float = end_time - start_time

                tui.praw(f'Random key generated in {tui.format_time(elapsed_time, decimal_places=4)}!\n')
                print_private_key(key)
                tui.praw('Press any key to finish\n')
                kb.read_key()

            elif action == 'k':
                print_title()
                tui.praw('PROCESS KEY\n\n')
                key: rsa.PrivateKey = private_key_input()
                print_private_key(key, verbose=True)
                tui.praw('Press any key to finish\n')
                kb.read_key()

            elif action == 'f':
                print_title()
                tui.praw('FACTORIZATION ATTACK\n\n')
                public_key: rsa.PublicKey = public_key_input(accept_private_keys=False)
                tui.praw('\nFactorizing...\n')

                start_time: float = time.time()
                key: rsa.PrivateKey = rsa.factorize(public_key)
                end_time: float = time.time()
                elapsed_time: float = end_time - start_time

                tui.praw(f'Private key cracked in {tui.format_time(elapsed_time, decimal_places=4)}!\n')
                print_private_key(key)
                tui.praw('Press any key to finish\n')
                kb.read_key()

            elif action == 'e':
                print_title()
                tui.praw('ENCRYPT\n\n')
                tui.praw('[T] Text\n')
                tui.praw('[F] File\n')
                tui.praw('[I] Integer\n')
                tui.praw('[P] PurpleMind\n\n')
                sub_action: str = kb.read_key()

                ciphertext: rsa.CipherText | None = None

                if sub_action == 't':
                    print_title()
                    tui.praw('ENCRYPT TEXT\n\n')
                    key: rsa.PublicKey = public_key_input()

                    tui.praw('\nFor multiline text, add a backslash to the end of every line except the last.\n\nEnter text:\n')
                    plaintext: str = ''
                    first_line: bool = True
                    while True:
                        line: str = tui.iraw(' > ' if first_line else '.. ')
                        if line.endswith('\\'):
                            plaintext += line[:-1] + '\n'
                        else:
                            plaintext += line
                            break
                        first_line = False
                    plaintext: bytes = plaintext.encode('utf-8')

                    tui.praw('\nEncrypting...\n')
                    start_time: float = time.time()
                    ciphertext = rsa.encrypt_bytes(plaintext, key)
                    end_time: float = time.time()
                    elapsed_time: float = end_time - start_time
                    tui.praw(f'Encrypted in {tui.format_time(elapsed_time, decimal_places=4)}!\n')

                elif sub_action == 'f':
                    print_title()
                    tui.praw('ENCRYPT FILE\n\n')
                    key: rsa.PublicKey = public_key_input()

                    tui.praw('\nEnter file path relative to "input" folder: ')
                    path: str = os.path.join('input', tui.iraw())
                    tui.praw('\nLoading file...\n')
                    start_time: float = time.time()
                    with open(path, 'rb') as f:
                        plaintext: bytes = f.read()
                    file_extension: str = path.rpartition('.')[2]
                    plaintext: bytes = file_extension.encode('utf-8') + b'.' + plaintext
                    end_time: float = time.time()
                    elapsed_time: float = end_time - start_time
                    tui.praw(f'Loaded in {tui.format_time(elapsed_time, decimal_places=4)}!')

                    tui.praw('\nEncrypting...\n')
                    start_time: float = time.time()
                    ciphertext = rsa.encrypt_bytes(plaintext, key)
                    end_time: float = time.time()
                    elapsed_time: float = end_time - start_time
                    tui.praw(f'Encrypted in {tui.format_time(elapsed_time, decimal_places=4)}!\n')

                elif sub_action == 'i':
                    print_title()
                    tui.praw('ENCRYPT INTEGER\n\n')
                    key: rsa.PublicKey = public_key_input()
                    tui.praw('\nEnter integer: ')
                    plaintext: int = int(tui.iraw())

                    tui.praw('\nEncrypting...\n')
                    start_time: float = time.time()
                    ciphertext = rsa.encrypt_int(plaintext, key)
                    end_time: float = time.time()
                    elapsed_time: float = end_time - start_time
                    tui.praw(f'Encrypted in {tui.format_time(elapsed_time, decimal_places=4)}!\n')

                elif sub_action == 'p':
                    print_title()
                    # noinspection SpellCheckingInspection
                    tui.praw(f'PURPLEMIND ENCRYPTION\nReplicates the behavior of this website: https://www.purplemindcreations.com/rsa-encryption-helper\nFor more information, see this video: https://www.youtube.com/watch?v=EY6scAHNgZw{PURPLEMIND_PUBLIC_KEY_STR}\n\n')
                    key: rsa.PublicKey = public_key_input()

                    tui.praw('\nNOTE: The first 30 characters will not be encrypted!\nFor multiline text, add a backslash to the end of every line except the last.\n\nEnter text:\n')
                    plaintext: str = ''
                    first_line: bool = True
                    while True:
                        line: str = tui.iraw(' > ' if first_line else '.. ')
                        if line.endswith('\\'):
                            plaintext += line[:-1] + '\n'
                        else:
                            plaintext += line
                            break
                        first_line = False

                    ciphertext_with_words: str = encrypt_purplemind(plaintext, key)
                    tui.praw(f'\nENCRYPTED DATA\n\n{ciphertext_with_words}\n\n')
                    tui.praw('Press any key to finish\n')
                    kb.read_key()
                else:
                    tui.praw('Invalid input!\n')
                    tui.praw('Press any key to finish\n')
                    kb.read_key()

                if ciphertext is not None:
                    tui.praw(f'\nENCRYPTED DATA\n\nLength: {ciphertext.bit_length} bits\n\n')
                    if ciphertext.bit_length <= 10000:
                        tui.praw(f'Hexadecimal\n0x{hex(ciphertext.data)[2:].zfill(ciphertext.hex_length)}\n\nDecimal\n{str(ciphertext.data).zfill(ciphertext.decimal_length)}\n\n')
                    else:
                        tui.praw(f'[Data is over 10000 bits long and is too large to show]\n\n')

                    tui.praw('[F] Save encrypted data to file\nPress any other key to finish\n')
                    if kb.read_key() == 'f':
                        tui.praw('\nSaving...\n')

                        start_time: float = time.time()
                        with open('output/encrypted_data.dat', 'wb') as f:
                            f.write(pickle.dumps(ciphertext))
                        end_time: float = time.time()
                        elapsed_time: float = end_time - start_time

                        tui.praw(f'Saved to "output/encrypted_data.dat" in {tui.format_time(elapsed_time, decimal_places=4)}!\n\n')
                        tui.praw('Press any key to finish\n')
                        kb.read_key()

            elif action == 'd':
                print_title()
                tui.praw('DECRYPT\n\n')
                tui.praw('[T] Text\n')
                tui.praw('[F] File\n')
                tui.praw('[I] Integer\n')
                tui.praw('[P] PurpleMind\n\n')
                sub_action: str = kb.read_key()

                ciphertext: rsa.CipherText | None = None
                key: rsa.PrivateKey | None = None

                if sub_action == 't':
                    print_title()
                    tui.praw('DECRYPT TEXT\n\n')
                    key: rsa.PrivateKey = private_key_input()

                elif sub_action == 'f':
                    print_title()
                    tui.praw('DECRYPT FILE\n\n')
                    key: rsa.PrivateKey = private_key_input()

                elif sub_action == 'i':
                    print_title()
                    tui.praw('DECRYPT INTEGER\n\n')
                    key: rsa.PrivateKey = private_key_input()

                elif sub_action == 'p':
                    print_title()
                    # noinspection SpellCheckingInspection
                    tui.praw(f'PURPLEMIND DECRYPTION\nReverses the behavior of this website: https://www.purplemindcreations.com/rsa-encryption-helper\nFor more information, see this video: https://www.youtube.com/watch?v=EY6scAHNgZw{PURPLEMIND_PRIVATE_KEY_STR}\n\n')
                    key: rsa.PrivateKey = private_key_input()

                else:
                    tui.praw('Invalid input!\n')

                if sub_action in ('t', 'f', 'i'):
                    tui.praw('\n[F] Decrypt from file\nPress any other key to decrypt from text\n')
                    if kb.read_key() == 'f':
                        tui.praw('\nEnter file path relative to "input" folder: ')
                        path: str = os.path.join('input', tui.iraw())
                        tui.praw('Loading file...\n')

                        start_time: float = time.time()
                        with open(path, 'rb') as f:
                            ciphertext: rsa.CipherText = pickle.loads(f.read())
                        end_time: float = time.time()
                        elapsed_time: float = end_time - start_time

                        tui.praw(f'Loaded in {tui.format_time(elapsed_time, decimal_places=4)}!\n')
                    else:
                        tui.praw('\nIf using hexadecimal, add "0x" to the beginning of the data.\n\nEnter encrypted data: ')
                        data_str: str = tui.iraw()
                        data: int = int(data_str, 16 if data_str.startswith('0x') else 10)
                        tui.praw('Enter data length in bits, or leave blank to guess: ')
                        length_str: str = tui.iraw()
                        length: int
                        if length_str == '':
                            length = data.bit_length()
                        else:
                            length = int(length_str)

                if sub_action == 't':
                    tui.praw('\nDecrypting...\n')
                    start_time: float = time.time()
                    plaintext: bytes = rsa.decrypt_bytes(ciphertext, key)
                    plaintext: str = plaintext.decode('utf-8')
                    end_time: float = time.time()
                    elapsed_time: float = end_time - start_time
                    tui.praw(f'Decrypted in {tui.format_time(elapsed_time, decimal_places=4)}!\n')

                    tui.praw(f'\nDECRYPTED DATA\n\n{plaintext}\n\n')

                elif sub_action == 'f':
                    tui.praw('\nDecrypting...\n')
                    start_time: float = time.time()
                    plaintext: bytes = rsa.decrypt_bytes(ciphertext, key)
                    partitioned: tuple[bytes, bytes, bytes] = plaintext.partition(b'.')
                    file_extension: str = partitioned[0].decode('utf-8')
                    plaintext: bytes = partitioned[2]
                    end_time: float = time.time()
                    elapsed_time: float = end_time - start_time
                    tui.praw(f'Decrypted in {tui.format_time(elapsed_time, decimal_places=4)}!\n')

                    tui.praw(f'Saving...\n')
                    start_time: float = time.time()
                    with open(f'output/decrypted_data.{file_extension}', 'wb') as f:
                        f.write(plaintext)
                    end_time: float = time.time()
                    elapsed_time: float = end_time - start_time
                    tui.praw(f'Saved to "output/decrypted_data.{file_extension}" in {tui.format_time(elapsed_time, decimal_places=4)}!\n\n')

                elif sub_action == 'i':
                    tui.praw('\nDecrypting...\n')
                    start_time: float = time.time()
                    plaintext: int = rsa.decrypt_int(ciphertext, key)
                    end_time: float = time.time()
                    elapsed_time: float = end_time - start_time
                    tui.praw(f'Decrypted in {tui.format_time(elapsed_time, decimal_places=4)}!\n')

                    tui.praw(f'\nDECRYPTED DATA\n\n{plaintext}\n\n')

                elif sub_action == 'p':
                    tui.praw('\nPress ENTER twice after entering the data.\n\nEnter encrypted data:\n')
                    ciphertext: str = ''
                    first_line: bool = True
                    while True:
                        line: str = tui.iraw(' > ' if first_line else '.. ')
                        if line == '':
                            break
                        ciphertext += line[:-1] + '\n'
                        first_line = False

                    tui.praw('\nDecrypting...\n')
                    start_time: float = time.time()
                    plaintext: str = decrypt_purplemind(ciphertext, key)
                    end_time: float = time.time()
                    elapsed_time: float = end_time - start_time
                    tui.praw(f'Decrypted in {tui.format_time(elapsed_time, decimal_places=4)}!\n')

                    tui.praw(f'\nDECRYPTED DATA\n\n{plaintext}\n\n')

                tui.praw('Press any key to finish\n')
                kb.read_key()

        except Exception as e:
            tui.praw(f'{tui.ANSI.BRIGHT_RED}\n{'-' * 20}\nERROR: {e}\n\n{traceback.format_exc()}{'-' * 20}\n\nPress any key to finish\n')
            kb.read_key()
