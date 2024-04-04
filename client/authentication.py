import secrets
import hashlib
from math import prod
from web3 import Web3
from Crypto import Random
from Crypto.Random import random
from Crypto.Util import number
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
# Connect to an Ethereum node
w3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID'))

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


# Function to interpolate the polynomial and reconstruct the secret
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

# Function to authenticate the user
def authenticate(username, password):
    username_hash = hashlib.sha256(username.encode()).digest()
    password_hash = hashlib.sha256(password.encode()).digest()

    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)

    # Initial authentication
    encrypted_x, shares = contract.functions.getEncryptedDataAndShares(username_hash).call()
    x_coordinates = decrypt_data(password_hash, encrypted_x)

    # Final authentication
    reconstructed_secret = lagrange_interpolation(x_coordinates, shares, 0)
    success, p, q, g, h = contract.functions.authenticate(username_hash, password_hash, reconstructed_secret).call()

    if success:
        print("Authentication successful!")
        # Perform next session initialization if needed
        initialize_next_session(username, password, p, q, g, h)
    else:
        print("Authentication failed!")

# Function to initialize the next session
def initialize_next_session(username, password, p, q, g, h):
    r = secrets.randbelow(q)
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
    username_hash = hashlib.sha256(username.encode()).digest()

    # Encrypt the x-coordinates and setup parameters
    encrypted_x = encrypt_data(key, x_coordinates)
    encrypted_params = encrypt_data(key, [r, p, q, g, h])

    # Invoke the smart contract's registration function
    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
    tx_hash = contract.functions.register(encrypted_x, encrypted_params, shares, username_hash).transact()
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
    print(f"Registration successful! Transaction receipt: {tx_receipt}")

    pass

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

if __name__ == "__main__":
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    authenticate(username, password)