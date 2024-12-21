class FEAL:
    def __init__(self, key_size=64):
        """Initialize FEAL cipher with configurable key size (in bits)"""
        self.key_size = key_size
        self.num_rounds = 8  # Standard number of rounds for FEAL
        
    def _rot2(self, value, n):
        """Rotate 8-bit value left by n positions"""
        return ((value << n) | (value >> (8 - n))) & 0xFF
    
    def _s0(self, a, b):
        """S-box function S0"""
        return self._rot2((a + b) & 0xFF, 2)
    
    def _s1(self, a, b):
        """S-box function S1"""
        return self._rot2((a + b) & 0xFF, 4)
        
    def _f_function(self, input_data, k):
        """F-function for FEAL round"""
        f1 = input_data[0] ^ input_data[1]
        f2 = input_data[2] ^ input_data[3]
        
        f1 ^= k[0]
        f2 ^= k[1]
        
        f0 = self._s1(f1, f2 ^ k[2])
        f3 = self._s0(f2, f0 ^ k[3])
        f1 = self._s1(f0, f1 ^ f3)
        f2 = self._s0(f3, f2 ^ f1)
        
        return bytes([f0, f1, f2, f3])

    def _expand_key(self, key):
        """Expand the key into round keys"""
        if len(key) * 8 != self.key_size:
            raise ValueError(f"Key must be {self.key_size} bits")
            
        subkeys = []
        # Key expansion algorithm
        for i in range(self.num_rounds):
            round_key = bytes([
                key[(4*i) % len(key)],
                key[(4*i + 1) % len(key)],
                key[(4*i + 2) % len(key)],
                key[(4*i + 3) % len(key)]
            ])
            subkeys.append(round_key)
        return subkeys

    def encrypt_block(self, plaintext, key):
        """
        Encrypt a single 64-bit block using FEAL
        plaintext: 8 bytes
        key: key_size//8 bytes
        """
        if len(plaintext) != 8:
            raise ValueError("Plaintext block must be 8 bytes")
            
        subkeys = self._expand_key(key)
        
        # Split into left and right halves
        left = plaintext[:4]
        right = plaintext[4:]
        
        # Feistel network
        for i in range(self.num_rounds):
            new_right = bytes(x ^ y for x, y in zip(left, self._f_function(right, subkeys[i])))
            left = right
            right = new_right
            
        # Final swap
        return right + left

    def decrypt_block(self, ciphertext, key):
        """
        Decrypt a single 64-bit block using FEAL
        ciphertext: 8 bytes
        key: key_size//8 bytes
        """
        if len(ciphertext) != 8:
            raise ValueError("Ciphertext block must be 8 bytes")
            
        subkeys = self._expand_key(key)
        
        # Split into left and right halves
        left = ciphertext[:4]
        right = ciphertext[4:]
        
        # Feistel network in reverse
        for i in range(self.num_rounds - 1, -1, -1):
            new_right = bytes(x ^ y for x, y in zip(left, self._f_function(right, subkeys[i])))
            left = right
            right = new_right
            
        # Final swap
        return right + left

    def pad_message(self, message):
        """PKCS#7 padding"""
        pad_len = 8 - (len(message) % 8)
        return message + bytes([pad_len] * pad_len)

    def unpad_message(self, padded_message):
        """Remove PKCS#7 padding"""
        pad_len = padded_message[-1]
        return padded_message[:-pad_len]
