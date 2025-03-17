import pytest
import secrets
import hmac
import hashlib

from csb_cipher_lib import Shadowbourne, KeyManager, encrypt, decrypt

# Sample plaintext for testing.
SAMPLE_TEXT = b"Hello, Shadowbourne Cipher!"

# ------------------------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------------------------

def modify_ciphertext(ciphertext: bytes) -> bytes:
    """Flip a bit in the ciphertext to simulate tampering."""
    # Convert to mutable bytearray.
    ct = bytearray(ciphertext)
    # Flip a bit in the middle.
    if len(ct) > 10:
        ct[10] ^= 0x01
    return bytes(ct)

# ------------------------------------------------------------------------------
# Test Encryption and Decryption Cycle
# ------------------------------------------------------------------------------

def test_encrypt_decrypt_cycle():
    key = KeyManager.generate_random_key(32)  # 256-bit key
    # Encrypt using convenience function.
    ciphertext = encrypt(SAMPLE_TEXT, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    decrypted = decrypt(ciphertext, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    assert decrypted == SAMPLE_TEXT

# ------------------------------------------------------------------------------
# Test Wrong Key Decryption Fails
# ------------------------------------------------------------------------------

def test_wrong_key_decryption():
    key = KeyManager.generate_random_key(32)
    wrong_key = KeyManager.generate_random_key(32)
    ciphertext = encrypt(SAMPLE_TEXT, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    with pytest.raises(ValueError, match="Authentication failed"):
        # Trying to decrypt with a wrong key should raise an error.
        decrypt(ciphertext, wrong_key, rounds=64, block_size=16, mode="CSB", include_mac=True)

# ------------------------------------------------------------------------------
# Test Tampered Ciphertext Fails Authentication
# ------------------------------------------------------------------------------

def test_tampered_ciphertext():
    key = KeyManager.generate_random_key(32)
    ciphertext = encrypt(SAMPLE_TEXT, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    tampered = modify_ciphertext(ciphertext)
    with pytest.raises(ValueError, match="Authentication failed"):
        decrypt(tampered, key, rounds=64, block_size=16, mode="CSB", include_mac=True)

# ------------------------------------------------------------------------------
# Test Padding and Unpadding Functions Directly
# ------------------------------------------------------------------------------

def test_padding_unpadding():
    key = KeyManager.generate_random_key(32)
    cipher = Shadowbourne(key, rounds=64, block_size=16)
    
    # Test that padding followed by unpadding recovers original data.
    for data in [b"", b"123", b"ExactBlock16Bytes!!"]:
        padded = cipher.pad(data)
        unpadded = cipher.unpad(padded)
        assert unpadded == data

def test_invalid_padding():
    key = KeyManager.generate_random_key(32)
    cipher = Shadowbourne(key, rounds=64, block_size=16)
    
    # Create a padded message and then tamper with the padding.
    data = b"Test message"
    padded = cipher.pad(data)
    # Change the last byte (the pad length indicator) to an invalid value.
    tampered = padded[:-1] + b"\x00"
    with pytest.raises(ValueError, match="Invalid padding"):
        cipher.unpad(tampered)

# ------------------------------------------------------------------------------
# Test KeyManager Functions
# ------------------------------------------------------------------------------

def test_key_derivation_entropy():
    password = "mysecretpassword"
    key, salt = KeyManager.derive_key_from_password(password, key_size=32)
    # Check that the key has the expected length.
    assert len(key) == 32
    # Check that the entropy is at least 100 bits.
    assert KeyManager.check_key_entropy(key, min_entropy_bits=100)

def test_random_key_generation():
    key = KeyManager.generate_random_key(32)
    assert len(key) == 32
    # Check entropy (this is a rough estimate).
    assert KeyManager.check_key_entropy(key, min_entropy_bits=100)

# ------------------------------------------------------------------------------
# Run Tests
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    # Run pytest programmatically.
    pytest.main([__file__])
