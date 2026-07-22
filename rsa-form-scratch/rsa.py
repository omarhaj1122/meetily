"""RSA implemented from scratch.

Includes Miller-Rabin primality testing, the extended Euclidean algorithm
for modular inverses, RSA key generation, and integer/byte encryption and
decryption.
"""

import random

_LOW_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def is_probable_prime(n, k=40):
    """Miller-Rabin primality test. False positive probability <= 4^-k."""
    if n < 2:
        return False
    for p in _LOW_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    """Generate a random probable prime with exactly `bits` bits."""
    if bits < 2:
        raise ValueError("bits must be >= 2")
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def extended_gcd(a, b):
    """Return (g, x, y) such that a*x + b*y = g = gcd(a, b)."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def mod_inverse(a, m):
    """Return x such that (a * x) % m == 1."""
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"no modular inverse for {a} mod {m}")
    return x % m


def generate_keypair(bits=1024, e=65537):
    """Generate an RSA keypair. Returns ((e, n), (d, n))."""
    if bits < 8:
        raise ValueError("bits must be >= 8")
    half = bits // 2
    p = generate_prime(half)
    q = generate_prime(bits - half)
    while p == q:
        q = generate_prime(bits - half)

    n = p * q
    phi = (p - 1) * (q - 1)

    while extended_gcd(e, phi)[0] != 1:
        e += 2

    d = mod_inverse(e, phi)
    return (e, n), (d, n)


def encrypt_int(m, pubkey):
    e, n = pubkey
    if not (0 <= m < n):
        raise ValueError("message integer out of range for this key size")
    return pow(m, e, n)


def decrypt_int(c, privkey):
    d, n = privkey
    return pow(c, d, n)


def _chunk_size(n):
    # Largest byte width whose max value is still strictly less than n.
    return (n.bit_length() - 1) // 8


def encrypt_bytes(data: bytes, pubkey):
    """Encrypt bytes as a list of ciphertext ints. Returns (cipher_ints, length)."""
    e, n = pubkey
    size = _chunk_size(n)
    if size < 1:
        raise ValueError("key too small to encrypt data")

    chunks = [data[i:i + size] for i in range(0, len(data), size)] or [b""]
    cipher_ints = [encrypt_int(int.from_bytes(chunk, "big"), pubkey) for chunk in chunks]
    return cipher_ints, len(data)


def decrypt_bytes(cipher_ints, length, privkey):
    """Decrypt a list of ciphertext ints back into the original bytes."""
    d, n = privkey
    size = _chunk_size(n)
    num_chunks = len(cipher_ints)

    out = bytearray()
    for i, c in enumerate(cipher_ints):
        m = decrypt_int(c, privkey)
        # All chunks except the last are exactly `size` bytes wide; the
        # last chunk's width is whatever remains of the original length.
        width = size if i < num_chunks - 1 else length - size * (num_chunks - 1)
        out += m.to_bytes(width, "big")
    return bytes(out)

