#!/usr/bin/env python3
"""
csb_cipher.py

A Python library implementing the Shadowbourne cipher (CSB cipher) and basic key management using Argon2 for password-based key derivation.

Usage:
    from csb_cipher_lib import Shadowbourne, KeyManager, encrypt, decrypt

    # For symmetric encryption with a hex key:
    key = bytes.fromhex("your_hex_key_here")
    ciphertext = encrypt(b"Secret message", key, rounds=64, block_size=16, mode="CSB", include_mac=True)
    plaintext = decrypt(ciphertext, key, rounds=64, block_size=16, mode="CSB", include_mac=True)
"""

import os
import secrets
import hashlib
import hmac
import base64
import time
import math
from argon2.low_level import hash_secret_raw, Type

class Shadowbourne:
    """
    Shadowbourne cipher implementation.

    This cipher uses a Feistel network with a custom round function.
    It supports multiple modes via a unified interface:
      - "CSB": Custom Shadowbourne mode (with MAC)
      - "ECB": Electronic Code Book mode
      - "CBC": Cipher Block Chaining mode
      - "CTR": Counter mode
      - "GCM": A simplified GCM-like authenticated encryption mode
    """

    def __init__(self, key: bytes, rounds: int = 64, block_size: int = 16):
        self.key = key
        self.rounds = rounds
        self.block_size = block_size
        self.half_block = block_size // 2
        self.subkeys = self.generate_subkeys(key, rounds)
        self.sbox = self.generate_sbox(key)
        
    def generate_sbox(self, key: bytes) -> list:
        """Generate a 256-byte S-box based on the key."""
        sbox = list(range(256))
        j = 0
        for i in range(256):
            j = (j + sbox[i] + key[i % len(key)]) % 256
            sbox[i], sbox[j] = sbox[j], sbox[i]
        return sbox
        
    def generate_subkeys(self, key: bytes, rounds: int) -> list:
        """
        Generate subkeys for each round using HMAC-SHA256.
        Subkeys are derived by chaining digests until the block size is met.
        """
        subkeys = []
        derived_key = key
        for i in range(rounds):
            data = i.to_bytes(4, 'big')
            subkey_raw = b""
            temp_key = derived_key
            while len(subkey_raw) < self.block_size:
                temp_key = hmac.new(temp_key, data, hashlib.sha256).digest()
                subkey_raw += temp_key
            subkeys.append(subkey_raw[:self.block_size])
            derived_key = temp_key
        return subkeys
    
    def F(self, x: bytes, subkey: bytes) -> bytes:
        """
        Round function with S-box substitution, rotations, and diffusion.
        """
        x_int = int.from_bytes(x, 'big')
        subkey_int = int.from_bytes(subkey[:self.half_block], 'big')
        result = x_int ^ subkey_int

        # S-box substitution
        result_bytes = result.to_bytes(self.half_block, 'big')
        substituted = bytearray(self.half_block)
        for i in range(self.half_block):
            substituted[i] = self.sbox[result_bytes[i]]
        result = int.from_bytes(substituted, 'big')

        # Rotations and addition
        rotate_amount1 = (subkey[-1] % (self.half_block * 8 - 1)) + 1
        rotate_amount2 = (subkey[-2] % (self.half_block * 8 - 1)) + 1
        rotated1 = ((result << rotate_amount1) | (result >> ((self.half_block * 8) - rotate_amount1))) & ((1 << (self.half_block * 8)) - 1)
        added = (rotated1 + subkey_int) & ((1 << (self.half_block * 8)) - 1)
        rotated2 = ((added << rotate_amount2) | (added >> ((self.half_block * 8) - rotate_amount2))) & ((1 << (self.half_block * 8)) - 1)
        final = rotated2 ^ (subkey_int >> 1)
        
        # Extra diffusion via an additional rotation
        extra_rotate = (subkey[-3] % (self.half_block * 8 - 1)) + 1
        extra = ((final << extra_rotate) | (final >> ((self.half_block * 8) - extra_rotate))) & ((1 << (self.half_block * 8)) - 1)
        return extra.to_bytes(self.half_block, 'big')
    
    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt a single block using a Feistel network."""
        if len(block) != self.block_size:
            raise ValueError(f"Block must be {self.block_size} bytes long")
        L = block[:self.half_block]
        R = block[self.half_block:]
        for subkey in self.subkeys:
            f_output = self.F(R, subkey)
            temp = bytes(a ^ b for a, b in zip(L, f_output))
            L, R = R, temp
        # Final swap
        return R + L
    
    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt a single block using the Feistel network."""
        if len(block) != self.block_size:
            raise ValueError(f"Block must be {self.block_size} bytes long")
        L = block[self.half_block:]
        R = block[:self.half_block]
        for subkey in reversed(self.subkeys):
            temp = bytes(a ^ b for a, b in zip(R, self.F(L, subkey)))
            R, L = L, temp
        return L + R
    
    def pad(self, data: bytes) -> bytes:
        """Apply PKCS#7 padding."""
        pad_len = self.block_size - (len(data) % self.block_size)
        return data + bytes([pad_len] * pad_len)
    
    def unpad(self, data: bytes) -> bytes:
        """Remove and validate PKCS#7 padding."""
        if not data or len(data) % self.block_size != 0:
            raise ValueError("Invalid ciphertext length")
        pad_len = data[-1]
        if pad_len < 1 or pad_len > self.block_size:
            raise ValueError(f"Invalid padding length: {pad_len}")
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("Invalid PKCS#7 padding")
        return data[:-pad_len]
    
    # -------------------- Mode Implementations --------------------
    
    def encrypt_csb(self, plaintext: bytes) -> bytes:
        """Encrypt using CSB mode with a nonce and HMAC-based tag."""
        nonce = secrets.token_bytes(self.block_size)
        ciphertext = bytearray(nonce)
        padded = self.pad(plaintext)
        # CSB mode: process each block with varying operations based on a mode selector.
        for i in range(0, len(padded), self.block_size):
            block = padded[i:i+self.block_size]
            subkey_hash = hashlib.sha256(self.subkeys[i % len(self.subkeys)]).digest()
            mode_selector = subkey_hash[0] % 4

            if i == 0:
                prev_block = nonce
                counter = int.from_bytes(nonce, 'big')
            else:
                prev_block = bytes(ciphertext[-self.block_size:])
                counter = int.from_bytes(prev_block, 'big') + 1

            if mode_selector == 0:
                xored = bytes(a ^ b for a, b in zip(block, prev_block))
                encrypted_block = self.encrypt_block(xored)
            elif mode_selector == 1:
                counter_bytes = counter.to_bytes(self.block_size, 'big')
                keystream = self.encrypt_block(counter_bytes)
                encrypted_block = bytes(a ^ b for a, b in zip(block, keystream))
            elif mode_selector == 2:
                xored = bytes(a ^ b for a, b in zip(block, prev_block))
                cbc_result = self.encrypt_block(xored)
                counter_bytes = counter.to_bytes(self.block_size, 'big')
                keystream = self.encrypt_block(counter_bytes)
                encrypted_block = bytes(a ^ b for a, b in zip(cbc_result, keystream))
            else:  # mode_selector == 3
                counter_bytes = counter.to_bytes(self.block_size, 'big')
                keystream = self.encrypt_block(counter_bytes)
                ctr_result = bytes(a ^ b for a, b in zip(block, keystream))
                encrypted_block = self.encrypt_block(bytes(a ^ b for a, b in zip(ctr_result, prev_block)))

            ciphertext.extend(encrypted_block)

        tag = hmac.new(self.key, bytes(ciphertext), hashlib.sha256).digest()
        ciphertext.extend(tag)
        return bytes(ciphertext)
    
    def decrypt_csb(self, ciphertext: bytes) -> bytes:
        """Decrypt data encrypted with CSB mode."""
        if len(ciphertext) < self.block_size + 32:
            raise ValueError("Ciphertext too short for CSB mode")
        tag = ciphertext[-32:]
        ciphertext_body = ciphertext[:-32]
        expected_tag = hmac.new(self.key, ciphertext_body, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Authentication failed: Data has been tampered with")
        nonce = ciphertext_body[:self.block_size]
        encrypted_data = ciphertext_body[self.block_size:]
        plaintext = bytearray()
        for i in range(0, len(encrypted_data), self.block_size):
            encrypted_block = encrypted_data[i:i+self.block_size]
            subkey_hash = hashlib.sha256(self.subkeys[i % len(self.subkeys)]).digest()
            mode_selector = subkey_hash[0] % 4
            if i == 0:
                prev_block = nonce
                counter = int.from_bytes(nonce, 'big')
            else:
                prev_block = encrypted_data[i-self.block_size:i]
                counter = int.from_bytes(prev_block, 'big') + 1
            if mode_selector == 0:
                decrypted_block = self.decrypt_block(encrypted_block)
                plain_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
            elif mode_selector == 1:
                counter_bytes = counter.to_bytes(self.block_size, 'big')
                keystream = self.encrypt_block(counter_bytes)
                plain_block = bytes(a ^ b for a, b in zip(encrypted_block, keystream))
            elif mode_selector == 2:
                counter_bytes = counter.to_bytes(self.block_size, 'big')
                keystream = self.encrypt_block(counter_bytes)
                ctr_undone = bytes(a ^ b for a, b in zip(encrypted_block, keystream))
                decrypted_block = self.decrypt_block(ctr_undone)
                plain_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
            else:
                decrypted_block = self.decrypt_block(encrypted_block)
                xored = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
                counter_bytes = counter.to_bytes(self.block_size, 'big')
                keystream = self.encrypt_block(counter_bytes)
                plain_block = bytes(a ^ b for a, b in zip(xored, keystream))
            plaintext.extend(plain_block)
        return self.unpad(bytes(plaintext))
    
    def encrypt_ecb(self, plaintext: bytes) -> bytes:
        """Encrypt using ECB mode."""
        padded = self.pad(plaintext)
        ciphertext = bytearray()
        for i in range(0, len(padded), self.block_size):
            block = padded[i:i+self.block_size]
            ciphertext.extend(self.encrypt_block(block))
        return bytes(ciphertext)
    
    def decrypt_ecb(self, ciphertext: bytes) -> bytes:
        """Decrypt using ECB mode."""
        if len(ciphertext) % self.block_size != 0:
            raise ValueError("Ciphertext length must be a multiple of block size for ECB mode")
        plaintext = bytearray()
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i+self.block_size]
            plaintext.extend(self.decrypt_block(block))
        return self.unpad(bytes(plaintext))
    
    def encrypt_cbc(self, plaintext: bytes) -> bytes:
        """Encrypt using CBC mode."""
        iv = secrets.token_bytes(self.block_size)
        padded = self.pad(plaintext)
        ciphertext = bytearray(iv)
        previous = iv
        for i in range(0, len(padded), self.block_size):
            block = padded[i:i+self.block_size]
            xored = bytes(a ^ b for a, b in zip(block, previous))
            encrypted_block = self.encrypt_block(xored)
            ciphertext.extend(encrypted_block)
            previous = encrypted_block
        return bytes(ciphertext)
    
    def decrypt_cbc(self, ciphertext: bytes) -> bytes:
        """Decrypt using CBC mode."""
        if len(ciphertext) < self.block_size or (len(ciphertext) - self.block_size) % self.block_size != 0:
            raise ValueError("Invalid ciphertext length for CBC mode")
        iv = ciphertext[:self.block_size]
        ciphertext_body = ciphertext[self.block_size:]
        plaintext = bytearray()
        previous = iv
        for i in range(0, len(ciphertext_body), self.block_size):
            block = ciphertext_body[i:i+self.block_size]
            decrypted_block = self.decrypt_block(block)
            plain_block = bytes(a ^ b for a, b in zip(decrypted_block, previous))
            plaintext.extend(plain_block)
            previous = block
        return self.unpad(bytes(plaintext))
    
    def encrypt_ctr(self, plaintext: bytes) -> bytes:
        """Encrypt using CTR mode."""
        nonce = secrets.token_bytes(self.block_size)
        ciphertext = bytearray(nonce)
        counter = int.from_bytes(nonce, 'big')
        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i+self.block_size]
            counter_bytes = counter.to_bytes(self.block_size, 'big')
            keystream = self.encrypt_block(counter_bytes)
            for j in range(len(block)):
                ciphertext.append(block[j] ^ keystream[j])
            counter += 1
        return bytes(ciphertext)
    
    def decrypt_ctr(self, ciphertext: bytes) -> bytes:
        """Decrypt using CTR mode."""
        if len(ciphertext) < self.block_size:
            raise ValueError("Ciphertext too short for CTR mode")
        nonce = ciphertext[:self.block_size]
        ciphertext_body = ciphertext[self.block_size:]
        plaintext = bytearray()
        counter = int.from_bytes(nonce, 'big')
        for i in range(0, len(ciphertext_body), self.block_size):
            block = ciphertext_body[i:i+self.block_size]
            counter_bytes = counter.to_bytes(self.block_size, 'big')
            keystream = self.encrypt_block(counter_bytes)
            for j in range(len(block)):
                plaintext.append(block[j] ^ keystream[j])
            counter += 1
        return bytes(plaintext)
    
    def encrypt_gcm(self, plaintext: bytes) -> bytes:
        """
        Encrypt using a simplified GCM-like mode.
        This mode uses CTR mode for encryption and an HMAC over the nonce and ciphertext as a tag.
        """
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM-like mode
        ciphertext = self._encrypt_ctr_internal(plaintext, nonce)
        tag = hmac.new(self.key, nonce + ciphertext, hashlib.sha256).digest()
        return nonce + ciphertext + tag
    
    def decrypt_gcm(self, ciphertext: bytes) -> bytes:
        """
        Decrypt using a simplified GCM-like mode.
        Extracts the 12-byte nonce and the 32-byte tag, verifies authentication, and decrypts.
        """
        if len(ciphertext) < 12 + 32:
            raise ValueError("Ciphertext too short for GCM mode")
        nonce = ciphertext[:12]
        tag = ciphertext[-32:]
        ciphertext_body = ciphertext[12:-32]
        expected_tag = hmac.new(self.key, nonce + ciphertext_body, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Authentication failed in GCM mode")
        return self._decrypt_ctr_internal(ciphertext_body, nonce)
    
    def _encrypt_ctr_internal(self, plaintext: bytes, nonce: bytes) -> bytes:
        """Internal CTR mode encryption used by GCM mode."""
        counter = int.from_bytes(nonce, 'big')
        ciphertext = bytearray()
        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i+self.block_size]
            counter_bytes = counter.to_bytes(self.block_size, 'big')
            keystream = self.encrypt_block(counter_bytes)
            for j in range(len(block)):
                ciphertext.append(block[j] ^ keystream[j])
            counter += 1
        return bytes(ciphertext)
    
    def _decrypt_ctr_internal(self, ciphertext: bytes, nonce: bytes) -> bytes:
        """CTR mode decryption is identical to encryption."""
        return self._encrypt_ctr_internal(ciphertext, nonce)
    
    # -------------------- Unified Interface --------------------
    
    def encrypt(self, plaintext: bytes, mode: str = "CSB", include_mac: bool = True) -> bytes:
        """
        Unified encryption interface.
        
        Supported modes: "CSB", "GCM", "CBC", "CTR", "ECB"
        """
        if not isinstance(plaintext, bytes):
            raise TypeError("Plaintext must be bytes")
        if mode == "CSB":
            return self.encrypt_csb(plaintext)
        elif mode == "ECB":
            return self.encrypt_ecb(plaintext)
        elif mode == "CBC":
            return self.encrypt_cbc(plaintext)
        elif mode == "CTR":
            return self.encrypt_ctr(plaintext)
        elif mode == "GCM":
            return self.encrypt_gcm(plaintext)
        else:
            raise ValueError(f"Unsupported mode in library: {mode}")
    
    def decrypt(self, ciphertext: bytes, mode: str = "CSB", include_mac: bool = True) -> bytes:
        """
        Unified decryption interface.
        
        Supported modes: "CSB", "GCM", "CBC", "CTR", "ECB"
        """
        if not isinstance(ciphertext, bytes):
            raise TypeError("Ciphertext must be bytes")
        if mode == "CSB":
            return self.decrypt_csb(ciphertext)
        elif mode == "ECB":
            return self.decrypt_ecb(ciphertext)
        elif mode == "CBC":
            return self.decrypt_cbc(ciphertext)
        elif mode == "CTR":
            return self.decrypt_ctr(ciphertext)
        elif mode == "GCM":
            return self.decrypt_gcm(ciphertext)
        else:
            raise ValueError(f"Unsupported mode in library: {mode}")

class KeyManager:
    """
    Key management using Argon2 for password-based key derivation.
    """

    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None, key_size: int = 32) -> tuple:
        if salt is None:
            salt = secrets.token_bytes(16)
        key = hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=4,
            memory_cost=65536,
            parallelism=4,
            hash_len=key_size,
            type=Type.I
        )
        return key, salt

    @staticmethod
    def generate_random_key(key_size: int = 32) -> bytes:
        return secrets.token_bytes(key_size)
    
    @staticmethod
    def check_key_entropy(key: bytes, min_entropy_bits: int = 100) -> bool:
        if not key:
            return False
        freq = {}
        for b in key:
            freq[b] = freq.get(b, 0) + 1
        total = len(key)
        entropy_per_byte = 0.0
        for count in freq.values():
            p = count / total
            entropy_per_byte -= p * math.log2(p)
        total_entropy = entropy_per_byte * total
        return total_entropy >= min_entropy_bits

def encrypt(plaintext: bytes, key: bytes, rounds: int = 64, block_size: int = 16,
            mode: str = "CSB", include_mac: bool = True) -> bytes:
    """
    Convenience function to encrypt data.
    
    Returns the ciphertext.
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes")
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")
    cipher = Shadowbourne(key, rounds, block_size)
    return cipher.encrypt(plaintext, mode, include_mac)

def decrypt(ciphertext: bytes, key: bytes, rounds: int = 64, block_size: int = 16,
            mode: str = "CSB", include_mac: bool = True) -> bytes:
    """
    Convenience function to decrypt data.
    
    Returns the plaintext.
    """
    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes")
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")
    cipher = Shadowbourne(key, rounds, block_size)
    return cipher.decrypt(ciphertext, mode, include_mac)

__all__ = ["Shadowbourne", "KeyManager", "encrypt", "decrypt"]
