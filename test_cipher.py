from csb_cipher_lib import encrypt, decrypt, KeyManager

# Define a sample plaintext and key.
plaintext = b"Hello, Shadowbourne Cipher!"

# Generate a random key (256-bit)
key = KeyManager.generate_random_key(32)
print("Key (hex):", key.hex())

# Encrypt the plaintext using the CSB mode.
ciphertext = encrypt(plaintext, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
print("Ciphertext (base64):", ciphertext.hex())

# Decrypt the ciphertext.
decrypted = decrypt(ciphertext, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
print("Decrypted text:", decrypted.decode())
