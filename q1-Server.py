# q1-Server.py

import socket
from Crypto.Util import number
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256

HOST = "127.0.0.1"
PORT = 26625

N = 1024

def gen_pub_key(bits: int):
    """
    Generate a (p, g) where p = k*q + 1 with q prime and g has order q mod p.
    'bits': the bit-size for q (and roughly for p).
    """
    q = number.getPrime(bits)
    k = 1
    p = k * q + 1
    while not number.isPrime(p):
        k += 1
        p = k * q + 1

    # Find g of order q mod p
    while True:
        h = number.getRandomRange(2, p - 1)
        g = pow(h, (p - 1) // q, p)
        if g != 1:
            break
    return p, g

def int_to_fixed_bytes(x: int, length: int = N) -> bytes:
    #Serialize int to bytes (big-endian, zero-padded)
    b = x.to_bytes((x.bit_length() + 7) // 8, "big")
    if len(b) > length:
        raise ValueError("Integer too large to fit in fixed-length buffer")
    return b.rjust(length, b"\x00")

def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = []
    remaining = length
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Connection closed while receiving data")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)

def get_encrypted_secret(SS: int) -> bytes:
    """
    Derive AES-256 key from SS via SHA-256
    AES-CBC encrypt Lily-Secret.txt
    return iv || ciphertext.
    """
    SS_bytes = SS.to_bytes((SS.bit_length() + 7) // 8, "big")
    key = sha256(SS_bytes).digest()  # 32 bytes
    iv = get_random_bytes(AES.block_size)  # 16 bytes
    data = open("Lily-Secret.txt", "rb").read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return iv + ciphertext

def handle_client(conn: socket.socket):
    p, g = gen_pub_key(bits=8 * N // 2)  # ~4096-bit q -> ~4096-8192-bit p; fits in 1024 bytes
    a = number.getRandomRange(2, p - 1)

    # A = g^a mod p
    A = pow(g, a, p)

    # Send p, g, A (each exactly N bytes, big-endian)
    conn.sendall(int_to_fixed_bytes(p, N))
    conn.sendall(int_to_fixed_bytes(g, N))
    conn.sendall(int_to_fixed_bytes(A, N))

    # Receive B (exactly N bytes)
    B_bytes = recv_exact(conn, N)
    B = int.from_bytes(B_bytes, "big")

    # Compute shared secret SS = B^a mod p
    SS = pow(B, a, p)

    # AES-CBC using key: SHA-256(SS)
    # send iv||ciphertext
    payload = get_encrypted_secret(SS)
    conn.sendall(payload)

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[+] Lily's server listening on {HOST}:{PORT}")
        try:
            while True:
                conn, addr = s.accept()
                with conn:
                    print(f"[+] Connection from {addr}")
                    try:
                        handle_client(conn)
                        print("[+] Served one client, closing connection")
                    except Exception as e:
                        print(f"[!] Error while handling client: {e}")
        except KeyboardInterrupt:
            print("\n[+] Shutting down.")

if __name__ == "__main__":
    main()
