# csb_cipher_lib

**csb_cipher_lib** is a Python cryptographic library that implements the Shadowbourne cipher (also known as the CSB cipher) along with key management using Argon2 for secure password-based key derivation. This library provides a unified interface for multiple encryption modes including:

- **CSB** – Custom Shadowbourne mode with MAC-based authentication  
- **ECB** – Electronic Code Book mode  
- **CBC** – Cipher Block Chaining mode  
- **CTR** – Counter mode  
- **GCM** – A simplified GCM-like authenticated encryption mode  

> **Note:** While this library implements its own custom cipher (CSB mode), it also provides implementations for common modes (ECB, CBC, CTR, GCM) using the underlying Shadowbourne block functions.

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Installation](#installation)
4. [Usage](#usage)
   - [Basic Encryption and Decryption](#basic-encryption-and-decryption)
   - [Using Different Modes](#using-different-modes)
   - [Key Derivation from a Password](#key-derivation-from-a-password)
   - [File Encryption and Decryption](#file-encryption-and-decryption)
5. [API Reference](#api-reference)
   - [Shadowbourne Class](#shadowbourne-class)
   - [KeyManager Class](#keymanager-class)
   - [Convenience Functions](#convenience-functions)
6. [Running Tests](#running-tests)
7. [Dependencies](#dependencies)
8. [Contributing](#contributing)
9. [License](#license)
10. [Acknowledgements](#acknowledgements)

---

## Overview

**csb_cipher_lib** implements the Shadowbourne cipher—a custom encryption algorithm built on a Feistel network with a unique round function. In addition to the CSB mode (which provides built-in authentication via HMAC), the library supports other modes (ECB, CBC, CTR, and GCM) to give you flexibility in how you encrypt your data. Secure key management is provided through random key generation and password-based key derivation using Argon2.

---

## Features

- **Custom Encryption (CSB Mode):**  
  Utilizes a Feistel network with a custom round function and provides message authentication.

- **Multiple Modes:**  
  Supports standard encryption modes:
  - **ECB (Electronic Code Book)**
  - **CBC (Cipher Block Chaining)**
  - **CTR (Counter)**
  - **GCM (GCM-like authenticated encryption)**
  
- **Key Management:**  
  - Generate random keys.
  - Derive keys from passwords securely using Argon2.

- **Input Validation:**  
  Ensures that plaintext, ciphertext, and keys are provided as bytes, raising clear errors when they are not.

- **Comprehensive Testing:**  
  An extensive test suite covers encryption cycles, edge cases, parameter variations, and even avalanche effects.

---

## Installation

### From Source (Editable Mode)

1. **Clone the Repository:**
   ```bash
   git clone <repository_url>
   cd <repository_folder>
Install the Package:
bash
Copy
pip install -e .
Future PyPI Installation
When published, you can install via:

bash
Copy
pip install csb_cipher_lib
Usage
Basic Encryption and Decryption
python
Copy
from csb_cipher_lib import encrypt, decrypt, KeyManager

# Generate a random 256-bit key (32 bytes)
key = KeyManager.generate_random_key(32)

plaintext = b"Secret message using Shadowbourne Cipher!"
# Encrypt using the default CSB mode with MAC authentication
ciphertext = encrypt(plaintext, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
print("Ciphertext (hex):", ciphertext.hex())

# Decrypt the ciphertext
decrypted = decrypt(ciphertext, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
print("Decrypted text:", decrypted.decode())
Using Different Modes
python
Copy
from csb_cipher_lib import encrypt, decrypt, KeyManager

key = KeyManager.generate_random_key(32)
plaintext = b"Data to be encrypted in different modes."

# Encrypt using CBC mode:
ciphertext_cbc = encrypt(plaintext, key, rounds=64, block_size=16, mode="CBC", include_mac=True)
decrypted_cbc = decrypt(ciphertext_cbc, key, rounds=64, block_size=16, mode="CBC", include_mac=True)
print("CBC decrypted:", decrypted_cbc.decode())

# Encrypt using CTR mode:
ciphertext_ctr = encrypt(plaintext, key, rounds=64, block_size=16, mode="CTR", include_mac=True)
decrypted_ctr = decrypt(ciphertext_ctr, key, rounds=64, block_size=16, mode="CTR", include_mac=True)
print("CTR decrypted:", decrypted_ctr.decode())

# Encrypt using GCM mode:
ciphertext_gcm = encrypt(plaintext, key, rounds=64, block_size=16, mode="GCM", include_mac=True)
decrypted_gcm = decrypt(ciphertext_gcm, key, rounds=64, block_size=16, mode="GCM", include_mac=True)
print("GCM decrypted:", decrypted_gcm.decode())
Key Derivation from a Password
python
Copy
from csb_cipher_lib import KeyManager

password = "my_super_secret_password"
key, salt = KeyManager.derive_key_from_password(password, key_size=32)
print("Derived key (hex):", key.hex())
print("Salt (hex):", salt.hex())
File Encryption and Decryption
python
Copy
from csb_cipher_lib import encrypt, decrypt, KeyManager

# Encrypt a file
with open("example.txt", "rb") as f:
    file_data = f.read()

key = KeyManager.generate_random_key(32)
encrypted_data = encrypt(file_data, key, rounds=64, block_size=16, mode="CSB", include_mac=True)

with open("example.txt.enc", "wb") as f:
    f.write(encrypted_data)

# Later, to decrypt the file:
with open("example.txt.enc", "rb") as f:
    encrypted_data = f.read()

decrypted_data = decrypt(encrypted_data, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
with open("example_decrypted.txt", "wb") as f:
    f.write(decrypted_data)
API Reference
Shadowbourne Class
__init__(self, key: bytes, rounds: int = 64, block_size: int = 16)
Initializes the cipher with the given key, number of rounds, and block size.

encrypt(self, plaintext: bytes, mode: str = "CSB", include_mac: bool = True) -> bytes
Encrypts plaintext using one of the supported modes ("CSB", "ECB", "CBC", "CTR", or "GCM").

decrypt(self, ciphertext: bytes, mode: str = "CSB", include_mac: bool = True) -> bytes
Decrypts ciphertext using one of the supported modes.

KeyManager Class
derive_key_from_password(password: str, salt: bytes = None, key_size: int = 32) -> tuple
Derives a key from a password using Argon2. Returns a tuple (key, salt).

generate_random_key(key_size: int = 32) -> bytes
Generates a random key of the specified size.

check_key_entropy(key: bytes, min_entropy_bits: int = 100) -> bool
Checks if the key has sufficient entropy.

Convenience Functions
encrypt(plaintext: bytes, key: bytes, rounds: int = 64, block_size: int = 16, mode: str = "CSB", include_mac: bool = True) -> bytes
Encrypts data using the Shadowbourne cipher. Returns the ciphertext.

decrypt(ciphertext: bytes, key: bytes, rounds: int = 64, block_size: int = 16, mode: str = "CSB", include_mac: bool = True) -> bytes
Decrypts data using the Shadowbourne cipher. Returns the plaintext.

Running Tests
A comprehensive test suite is provided using pytest.

Install pytest if needed:

bash
Copy
pip install pytest
Run tests from the project root:

bash
Copy
pytest
All tests should pass, ensuring that the library functions correctly and robustly.

Dependencies
Python 3.6 or higher
argon2-cffi
Contributing
Contributions are welcome! Please follow these steps:

Fork the repository.
Create a feature branch.
Add tests and update documentation.
Submit a pull request.
License
This project is licensed under the MIT License. See the LICENSE file for details.

Acknowledgements
Thanks to the developers of argon2-cffi for providing key derivation functionality.
Inspired by the need for flexible, custom cryptographic tools in Python.