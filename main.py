import rsa_encryption as rsa
import soup_tui as tui
import soup_tui.keyboard as kb
import traceback
import pickle
import time

# All "PurpleMind"-related things refer to this YouTube video: https://www.youtube.com/watch?v=EY6scAHNgZw
# The online encrypter PurpleMind provides is here: https://www.purplemindcreations.com/rsa-encryption-helper
# The explanation of their encrypter is here: https://www.purplemindcreations.com/explanation

# noinspection SpellCheckingInspection
PURPLEMIND_ENGLISH_WORDS: list[str] = [
    'apple', 'banana', 'cherry', 'dog', 'elephant', 'fish', 'grape', 'hat', 'ink', 'jump',
    'kangaroo', 'lion', 'monkey', 'net', 'orange', 'peach', 'quilt', 'rose', 'sun', 'tree',
    'umbrella', 'vulture', 'whale', 'xenon', 'yellow', 'zebra'
]

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
def public_key_input() -> rsa.PublicKey:
    tui.praw('If using hexadecimal, add "0x" to the beginning of the key.\n\nEnter public key: ')
    modulus: str = tui.iraw()
    tui.praw('Enter public exponent: ')
    exponent: int = int(tui.iraw())

    modulus: int = int(modulus, 16 if modulus.startswith('0x') else 10)
    return rsa.PublicKey(modulus, public_exponent=exponent)

# noinspection PyShadowingNames
def print_private_key(key: rsa.PrivateKey) -> None:
    tui.praw(f'\nPRIVATE KEY\n\nHexadecimal\n{hex(key.p)},{hex(key.q)}\n\nDecimal\n{key.p},{key.q}\n\nd = {key.exponent}\n\n')
    tui.praw(f'PUBLIC KEY\n\nHexadecimal\n{hex(key.public_key.modulus)}\n\nDecimal\n{key.public_key.modulus}\n\ne = {key.public_key.exponent}\n\n')

while True:
    print_title()
    tui.praw('[E] Encrypt (Only Text and File modes implemented)\n')
    tui.praw('[D] Decrypt (Not yet implemented)\n')
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
            print_private_key(key)
            tui.praw('Press any key to finish\n')
            kb.read_key()

        elif action == 'f':
            print_title()
            tui.praw('FACTORIZATION ATTACK\n\n')
            public_key: rsa.PublicKey = public_key_input()
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

            plaintext: bytes | None = None
            ciphertext: rsa.CipherText | None = None
            key: rsa.PublicKey | None = None

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
                plaintext = plaintext.encode('utf-8')

            elif sub_action == 'f':
                print_title()
                tui.praw('ENCRYPT FILE\n\n')
                key: rsa.PublicKey = public_key_input()

                tui.praw('\nEnter file path: ')
                path: str = tui.iraw()
                tui.praw('\nLoading file...\n')
                start_time: float = time.time()
                with open(path, 'rb') as f:
                    plaintext: bytes = f.read()
                end_time: float = time.time()
                elapsed_time: float = end_time - start_time
                tui.praw(f'Loaded in {tui.format_time(elapsed_time, decimal_places=4)}!')

            elif sub_action == 'i':
                print_title()
                tui.praw('ENCRYPT INTEGER\n\n')
                key: rsa.PublicKey = public_key_input()

            elif sub_action == 'p':
                print_title()
                # noinspection SpellCheckingInspection
                tui.praw('PURPLEMIND ENCRYPTION\nReplicates behavior of this website: https://www.purplemindcreations.com/rsa-encryption-helper\nFor more information, see this video: https://www.youtube.com/watch?v=EY6scAHNgZw\n\n')
                key: rsa.PublicKey = public_key_input()

            else:
                tui.praw('Invalid input!\n')

            if plaintext is not None:
                tui.praw('\nEncrypting...\n')
                start_time: float = time.time()
                ciphertext = rsa.encrypt_bytes(plaintext, key)
                end_time: float = time.time()
                elapsed_time: float = end_time - start_time
                tui.praw(f'Encrypted in {tui.format_time(elapsed_time, decimal_places=4)}!\n')

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

                    tui.praw(f'Saved to "outputs/encrypted_data.dat" in {tui.format_time(elapsed_time, decimal_places=4)}!\n\n')
                    tui.praw('Press any key to finish\n')
                    kb.read_key()

    except Exception as e:
        tui.praw(f'{tui.ANSI.BRIGHT_RED}\n{'-' * 20}\nERROR: {e}\n\n{traceback.format_exc()}{'-' * 20}\n\nPress any key to finish\n')
        kb.read_key()
