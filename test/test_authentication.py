import time
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

# Connect to an Ethereum node
w3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID'))

# Define the security parameter (bit length)
security = 256

# Define the contract address and ABI
CONTRACT_ADDRESS = '0x...'  # Replace with your contract address
CONTRACT_ABI = [...] # Replace with your contract ABI

def encrypt_data(key, data):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    padded_data = PKCS7(algorithms.AES.block_size).padder().update(data) + PKCS7(algorithms.AES.block_size).padder().finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted_data

# Function to generate registration data for a single client
def generate_registration_data(password, username):
    # ... (existing code to generate registration data) ...
    # Generate p and q
    p = number.getPrime(security, secrets.randbits)
    print("p = ", p)

    r = 1
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
    r=secrets.randbelow(q)
    g = secrets.choice([x for x in G if x != 1])
    print("g = ", g)
    h = secrets.choice([x for x in G if x != 1 and x != g])
    print("h = ", h)

    # Generate the one-time secret S'
    S = int.from_bytes(password.encode(), byteorder='big')
    S_prime = (pow(g, S, p) * pow(h, r, p)) % p

    # Generate coefficients and x-coordinates for Shamir's scheme
    n = 3  # Threshold for secret reconstruction
    coefficients = [S_prime] + [secrets.choice(G) for _ in range(1, n)]
    x_coordinates = [secrets.choice(G) for _ in range(1, n + 1)]

    # Evaluate the polynomial to get shares
    shares = [sum(coeff * pow(x, i, q) for i, coeff in enumerate(coefficients)) % q for x in x_coordinates]

    # Hash the password and username to get the encryption key and username_hash
    key = hashlib.sha256(password.encode()).digest()
    username_hash = hashlib.sha256(username.encode()).digest()

    # Encrypt the x-coordinates and setup parameters
    encrypted_x = encrypt_data(key, x_coordinates)
    encrypted_params = encrypt_data(key, [r, p, q, g, h])
    return encrypted_x, encrypted_params, shares, username_hash

# Function to authenticate a single client
def authenticate_client(contract, username, password):
    username_hash = hashlib.sha256(username.encode()).digest()
    password_hash = hashlib.sha256(password.encode()).digest()

    start_time = time.time()

    # Initial authentication
    encrypted_x, shares = contract.functions.getEncryptedDataAndShares(username_hash).call()
    x_coordinates = decrypt_data(password_hash, encrypted_x)

    # Final authentication
    reconstructed_secret = lagrange_interpolation(x_coordinates, shares, 0)
    success, p, q, g, h = contract.functions.authenticate(username_hash, password_hash, reconstructed_secret).call()

    end_time = time.time()
    gas_used = 0  # Placeholder for gas cost calculation (replace with your implementation)

    return end_time - start_time, gas_used, success

# Helper function to interpolate the polynomial and reconstruct the secret
def lagrange_interpolation(x_coordinates, shares, x):
    n = len(x_coordinates)
    result = 0
    for i in range(n):
        term = shares[i]
        for j in range(n):
            if j != i:
                term *= (x - x_coordinates[j]) // (x_coordinates[i] - x_coordinates[j])
        result += term
    return result

# Helper function to decrypt data (replace with your implementation)
def decrypt_data(key, encrypted_data):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()

    padded_data = encrypted_data
    decrypted_data = decryptor.update(padded_data) + decryptor.finalize()

    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data

# Test the authentication function with multiple clients
def test_authentication(num_clients):
    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
    latencies = []
    gas_costs = []
    success_counts = []

    for i in range(1,num_clients,5):
        password = f"password{i}"
        username = f"user{i}"
        encrypted_x, encrypted_params, shares, username_hash = generate_registration_data(password, username)
        latency, gas_cost, success = authenticate_client(contract, username, password)
        latencies.append(latency)
        gas_costs.append(gas_cost)
        success_counts.append(int(success))

    avg_latency = sum(latencies) / num_clients
    avg_gas_cost = sum(gas_costs) / num_clients
    success_rate = sum(success_counts) / num_clients

    print(f"Average latency for {num_clients} clients: {avg_latency:.6f} seconds")
    print(f"Average gas cost for {num_clients} clients: {avg_gas_cost:.0f} gas units")
    print(f"Success rate for {num_clients} clients: {success_rate:.2f}")

if __name__ == "__main__":
    num_clients = 25  # Number of clients to simulate
    test_authentication(num_clients)