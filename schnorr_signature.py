import hashlib
import random

class SchnorrSignature:
    def __init__(self, curve, G, n):
        """
        Initialize with same curve parameters as EC-ElGamal
        curve: EllipticCurve instance
        G: generator point
        n: order of G
        """
        self.curve = curve
        self.G = G
        self.n = n
        
    def generate_keypair(self):
        """Generate private and public key pair"""
        private_key = random.randrange(1, self.n)
        public_key = self.curve.multiply_point(private_key, self.G)
        return private_key, public_key
        
    def _hash(self, message, R):
        """Hash function for signature scheme"""
        h = hashlib.sha256()
        h.update(message)
        h.update(str(R.x).encode())
        h.update(str(R.y).encode())
        return int.from_bytes(h.digest(), 'big') % self.n
        
    def sign(self, message, private_key):
        """
        Generate Schnorr signature for message using private key
        Returns (R, s) signature tuple
        """
        k = random.randrange(1, self.n)
        R = self.curve.multiply_point(k, self.G)
        e = self._hash(message, R)
        s = (k + e * private_key) % self.n
        return (R, s)
        
    def verify(self, message, signature, public_key):
        """
        Verify Schnorr signature using public key
        Returns True if signature is valid
        """
        R, s = signature
        e = self._hash(message, R)
        
        # Calculate sG
        sG = self.curve.multiply_point(s, self.G)
        
        # Calculate R + eP
        eP = self.curve.multiply_point(e, public_key)
        R_prime = self.curve.add_points(R, eP)
        
        return sG.x == R_prime.x and sG.y == R_prime.y
