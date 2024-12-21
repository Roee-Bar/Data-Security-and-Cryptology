import os

class CBC:
    def __init__(self, block_cipher):
        """
        Initialize CBC mode with a block cipher
        block_cipher should have encrypt_block and decrypt_block methods
        """
        self.cipher = block_cipher
        self.block_size = 8  # FEAL uses 64-bit (8 byte) blocks

    def generate_iv(self):
        """Generate a random initialization vector"""
        return os.urandom(self.block_size)

    def encrypt(self, plaintext, key, iv):
        """
        Encrypt using CBC mode
        plaintext: bytes to encrypt
        key: encryption key
        iv: initialization vector
        """
        # Pad plaintext
        padded_plaintext = self.cipher.pad_message(plaintext)
        
        # Initialize
        previous = iv
        ciphertext = b''
        
        # Process each block
        for i in range(0, len(padded_plaintext), self.block_size):
            block = padded_plaintext[i:i + self.block_size]
            # XOR with previous ciphertext block (or IV for first block)
            xored = bytes(x ^ y for x, y in zip(block, previous))
            # Encrypt the XORed block
            encrypted_block = self.cipher.encrypt_block(xored, key)
            ciphertext += encrypted_block
            previous = encrypted_block
            
        return ciphertext

    def decrypt(self, ciphertext, key, iv):
        """
        Decrypt using CBC mode
        ciphertext: bytes to decrypt
        key: decryption key
        iv: initialization vector
        """
        if len(ciphertext) % self.block_size != 0:
            raise ValueError("Ciphertext length must be multiple of block size")
            
        # Initialize
        previous = iv
        plaintext = b''
        
        # Process each block
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]
            # Decrypt the block
            decrypted_block = self.cipher.decrypt_block(block, key)
            # XOR with previous ciphertext block (or IV for first block)
            plaintext += bytes(x ^ y for x, y in zip(decrypted_block, previous))
            previous = block
            
        # Remove padding
        return self.cipher.unpad_message(plaintext)
