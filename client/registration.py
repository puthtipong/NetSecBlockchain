import secrets
import hashlib
from math import ceil
from web3 import Web3
from Crypto import Random
from Crypto.Random import random
from Crypto.Util import number
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend


def encrypt_data(key, data):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    padded_data = PKCS7(algorithms.AES.block_size).padder().update(data) + PKCS7(algorithms.AES.block_size).padder().finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted_data

# Connect to an Ethereum node
w3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID'))

# Define the security parameter (bit length)
security = 256

# Generate p and q
p = number.getPrime(security, secrets.randbits)
print("p = ", p)

k = 1
while True:
    q = k * p + 1
    if number.isPrime(q):
        print("q = ", q)
        break
    k += 1

# Compute elements of G = {i^r mod q | i in Z_q*}
G = []
for i in range(1, q):
    G.append(pow(i, k, q))
G = list(set(G))
print("Order of G = {i^r mod q | i in Z_q*} is " + str(len(G)) + " (must be equal to p).")

# Choose g and h from G
g = secrets.choice([x for x in G if x != 1])
print("g = ", g)
h = secrets.choice([x for x in G if x != 1 and x != g])
print("h = ", h)

# Generate the one-time secret S'
r = secrets.randbelow(q)
password = input("Enter your password: ")
S = int.from_bytes(password.encode(), byteorder='big')
S_prime = (pow(g, S, p) * pow(h, r, p)) % p

# Generate coefficients and x-coordinates for Shamir's scheme
n = 3  # Threshold for secret reconstruction
coefficients = [S_prime] + [secrets.choice(G) for _ in range(1, n)]
x_coordinates = [secrets.randbelow(q) for _ in range(1, n + 1)]

# Evaluate the polynomial to get shares
shares = [sum(coeff * pow(x, i, q) for i, coeff in enumerate(coefficients)) % q for x in x_coordinates]

# Hash the password and username to get the encryption key and username_hash
key = hashlib.sha256(password.encode()).digest()
username = input("Enter your username: ")
username_hash = hashlib.sha256(username.encode()).digest()

# Encrypt the x-coordinates and setup parameters
encrypted_x = encrypt_data(key, x_coordinates)
encrypted_params = encrypt_data(key, [r, p, q, g, h])

# Invoke the smart contract's registration function
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
tx_hash = contract.functions.register(encrypted_x, encrypted_params, shares, username_hash).transact()
tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
print(f"Registration successful! Transaction receipt: {tx_receipt}")

