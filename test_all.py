import pytest
import secrets
import time
import math
import binascii

from csb_cipher_lib import Shadowbourne, KeyManager, encrypt, decrypt

SAMPLE_TEXT = b"Hello, Shadowbourne Cipher!"

# -------------------------------------------------------------------------------
# Helper Functions
# -------------------------------------------------------------------------------

def modify_ciphertext(ciphertext: bytes) -> bytes:
    """Flip a bit in the ciphertext to simulate tampering."""
    ct = bytearray(ciphertext)
    if len(ct) > 10:
        ct[10] ^= 0x01
    return bytes(ct)

def hamming_distance(b1: bytes, b2: bytes) -> int:
    """Calculate the Hamming distance between two byte sequences."""
    if len(b1) != len(b2):
        raise ValueError("Byte sequences must be of equal length")
    dist = 0
    for byte1, byte2 in zip(b1, b2):
        dist += bin(byte1 ^ byte2).count("1")
    return dist

# -------------------------------------------------------------------------------
# Basic Encryption/Decryption Cycle Tests
# -------------------------------------------------------------------------------

def test_encrypt_decrypt_cycle():
    key = KeyManager.generate_random_key(32)
    ciphertext = encrypt(SAMPLE_TEXT, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    decrypted = decrypt(ciphertext, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    assert decrypted == SAMPLE_TEXT

def test_empty_plaintext():
    key = KeyManager.generate_random_key(32)
    plaintext = b""
    ciphertext = encrypt(plaintext, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    decrypted = decrypt(ciphertext, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    assert decrypted == plaintext

def test_exact_block_plaintext():
    key = KeyManager.generate_random_key(32)
    plaintext = b"1234567890ABCDEF"  # 16 bytes exactly
    ciphertext = encrypt(plaintext, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    decrypted = decrypt(ciphertext, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    assert decrypted == plaintext

def test_long_message():
    key = KeyManager.generate_random_key(32)
    plaintext = b"A" * 10000  # 10KB
    ciphertext = encrypt(plaintext, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    decrypted = decrypt(ciphertext, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    assert decrypted == plaintext

# -------------------------------------------------------------------------------
# Parameterized Tests for Different Rounds and Block Sizes
# -------------------------------------------------------------------------------

@pytest.mark.parametrize("rounds, block_size", [
    (32, 16),
    (64, 16),
    (64, 32),
    (128, 16),
])
def test_parameterized_encryption(rounds, block_size):
    key = KeyManager.generate_random_key(32)
    plaintext = b"The quick brown fox jumps over the lazy dog."
    ciphertext = encrypt(plaintext, key, rounds=rounds, block_size=block_size, mode="CSB", include_mac=True)
    decrypted = decrypt(ciphertext, key, rounds=rounds, block_size=block_size, mode="CSB", include_mac=True)
    assert decrypted == plaintext

# -------------------------------------------------------------------------------
# Test Unsupported Mode Handling
# -------------------------------------------------------------------------------

def test_unsupported_mode():
    key = KeyManager.generate_random_key(32)
    with pytest.raises(ValueError, match="Unsupported mode"):
        encrypt(SAMPLE_TEXT, key, rounds=64, block_size=16, mode="FOO", include_mac=True)

# -------------------------------------------------------------------------------
# Test Handling of Non-bytes Input
# -------------------------------------------------------------------------------

def test_non_bytes_plaintext():
    key = KeyManager.generate_random_key(32)
    with pytest.raises(TypeError):
        encrypt("This is a string, not bytes", key, rounds=64, block_size=16, mode="CSB", include_mac=True)

def test_non_bytes_ciphertext():
    key = KeyManager.generate_random_key(32)
    with pytest.raises(TypeError):
        decrypt("Not bytes ciphertext", key, rounds=64, block_size=16, mode="CSB", include_mac=True)

def test_non_bytes_key():
    with pytest.raises(TypeError):
        encrypt(SAMPLE_TEXT, "Not a byte key", rounds=64, block_size=16, mode="CSB", include_mac=True)

def test_decrypt_non_bytes_input():
    key = KeyManager.generate_random_key(32)
    with pytest.raises(TypeError):
        decrypt(12345, key, rounds=64, block_size=16, mode="CSB", include_mac=True)

# -------------------------------------------------------------------------------
# Test Mismatched Parameters
# -------------------------------------------------------------------------------

def test_wrong_rounds():
    key = KeyManager.generate_random_key(32)
    ciphertext = encrypt(b"Test message", key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    with pytest.raises(Exception):
        decrypt(ciphertext, key, rounds=32, block_size=16, mode="CSB", include_mac=True)

def test_wrong_block_size():
    key = KeyManager.generate_random_key(32)
    ciphertext = encrypt(b"Test message", key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    with pytest.raises(Exception):
        decrypt(ciphertext, key, rounds=64, block_size=32, mode="CSB", include_mac=True)

# -------------------------------------------------------------------------------
# Test Modified Ciphertext Authentication (Tampering)
# -------------------------------------------------------------------------------

def test_modified_tag():
    key = KeyManager.generate_random_key(32)
    plaintext = b"Test message for tag modification."
    ciphertext = encrypt(plaintext, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    ct_list = list(ciphertext)
    ct_list[-32] ^= 0xFF
    modified_ciphertext = bytes(ct_list)
    with pytest.raises(ValueError, match="Authentication failed"):
        decrypt(modified_ciphertext, key, rounds=64, block_size=16, mode="CSB", include_mac=True)

# -------------------------------------------------------------------------------
# Test Multiple Encrypt/Decrypt Cycles
# -------------------------------------------------------------------------------

def test_multiple_cycles():
    key = KeyManager.generate_random_key(32)
    original = b"Repeat encryption and decryption test."
    ciphertext = encrypt(original, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    for _ in range(5):
        decrypted = decrypt(ciphertext, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
        assert decrypted == original
        ciphertext = encrypt(decrypted, key, rounds=64, block_size=16, mode="CSB", include_mac=True)

# -------------------------------------------------------------------------------
# Test Randomness: Encrypting Same Plaintext Twice Yields Different Ciphertext
# -------------------------------------------------------------------------------

def test_encrypt_randomness():
    key = KeyManager.generate_random_key(32)
    plaintext = b"Identical message"
    ciphertext1 = encrypt(plaintext, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    ciphertext2 = encrypt(plaintext, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    assert ciphertext1 != ciphertext2

# -------------------------------------------------------------------------------
# Avalanche Test: A single bit change in plaintext should cause a large difference in ciphertext
# -------------------------------------------------------------------------------

def test_avalanche_effect():
    key = KeyManager.generate_random_key(32)
    plaintext1 = b"Test message for avalanche effect."
    # Flip one bit in the plaintext: change the last byte by 1 bit.
    plaintext2 = bytearray(plaintext1)
    plaintext2[-1] ^= 0x01
    plaintext2 = bytes(plaintext2)
    
    ciphertext1 = encrypt(plaintext1, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    ciphertext2 = encrypt(plaintext2, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    
    # We need to compare only the ciphertext body (excluding nonce and tag) 
    # because nonce is random per encryption.
    # Here, we'll compare the entire ciphertext (they should be different),
    # and also compute the Hamming distance between them.
    assert ciphertext1 != ciphertext2
    
    # For avalanche, we expect a high Hamming distance relative to the total bits.
    # Remove nonce (first block) and tag (last 32 bytes)
    body1 = ciphertext1[16:-32]
    body2 = ciphertext2[16:-32]
    # Calculate Hamming distance (in bits)
    distance = hamming_distance(body1, body2)
    total_bits = len(body1) * 8
    # Require at least 40% of bits to be different, for example.
    assert distance > 0.4 * total_bits

# -------------------------------------------------------------------------------
# Test KeyManager Entropy Functionality
# -------------------------------------------------------------------------------

def test_key_derivation_entropy():
    password = "mysecretpassword"
    key, salt = KeyManager.derive_key_from_password(password, key_size=32)
    assert len(key) == 32
    assert KeyManager.check_key_entropy(key, min_entropy_bits=100)

def test_random_key_generation():
    key = KeyManager.generate_random_key(32)
    assert len(key) == 32
    assert KeyManager.check_key_entropy(key, min_entropy_bits=100)

# -------------------------------------------------------------------------------
# Optional: Performance Test (Does not assert, just prints duration)
# -------------------------------------------------------------------------------

def test_performance():
    key = KeyManager.generate_random_key(32)
    plaintext = b"A" * (1024 * 1024)  # 1 MB
    start = time.time()
    _ = encrypt(plaintext, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    duration = time.time() - start
    print(f"Encryption of 1MB took {duration:.4f} seconds")

# -------------------------------------------------------------------------------
# Run tests if this file is executed directly.
# -------------------------------------------------------------------------------

if __name__ == "__main__":
    pytest.main([__file__])
