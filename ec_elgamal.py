import random
from dataclasses import dataclass

@dataclass
class Point:
    x: int
    y: int
    infinity: bool = False

class EllipticCurve:
    """Simple elliptic curve over Fp: y^2 = x^3 + ax + b"""
    def __init__(self, p, a, b):
        """Initialize curve with prime p and parameters a, b"""
        self.p = p
        self.a = a
        self.b = b
        
    def add_points(self, P1, P2):
        """Add two points on the curve"""
        if P1.infinity:
            return P2
        if P2.infinity:
            return P1
            
        if P1.x == P2.x and P1.y != P2.y:
            return Point(0, 0, infinity=True)
            
        if P1.x == P2.x:
            # Point doubling
            if P1.y == 0:
                return Point(0, 0, infinity=True)
            lam = ((3 * P1.x * P1.x + self.a) * pow(2 * P1.y, -1, self.p)) % self.p
        else:
            # Point addition
            lam = ((P2.y - P1.y) * pow(P2.x - P1.x, -1, self.p)) % self.p
            
        x3 = (lam * lam - P1.x - P2.x) % self.p
        y3 = (lam * (P1.x - x3) - P1.y) % self.p
        
        return Point(x3, y3)

    def multiply_point(self, k, P):
        """Multiply point P by scalar k using double-and-add"""
        result = Point(0, 0, infinity=True)
        addend = P
        
        while k:
            if k & 1:
                result = self.add_points(result, addend)
            addend = self.add_points(addend, addend)
            k >>= 1
            
        return result

class ECElGamal:
    def __init__(self, curve, G, n):
        """
        Initialize with curve parameters
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
        
    def encrypt(self, message_point, public_key):
        """
        Encrypt a message point using recipient's public key
        Returns (c1, c2) tuple
        """
        k = random.randrange(1, self.n)
        c1 = self.curve.multiply_point(k, self.G)
        c2 = self.curve.add_points(message_point, 
                                 self.curve.multiply_point(k, public_key))
        return (c1, c2)
        
    def decrypt(self, ciphertext, private_key):
        """
        Decrypt (c1, c2) using private key
        Returns decrypted message point
        """
        c1, c2 = ciphertext
        s = self.curve.multiply_point(private_key, c1)
        s.y = (-s.y) % self.curve.p  # Negate y coordinate
        return self.curve.add_points(c2, s)

    def encode_message(self, message_bytes):
        """
        Simple message encoding into curve point
        Note: This is a basic implementation - production systems
        should use more sophisticated point encoding methods
        """
        x = int.from_bytes(message_bytes, 'big')
        while True:
            x = x % self.curve.p
            y_squared = (pow(x, 3, self.curve.p) + 
                        self.curve.a * x + self.curve.b) % self.curve.p
            y = pow(y_squared, (self.curve.p + 1) // 4, self.curve.p)
            if pow(y, 2, self.curve.p) == y_squared:
                return Point(x, y)
            x += 1

    def decode_message(self, point):
        """Decode message from curve point"""
        return point.x.to_bytes((point.x.bit_length() + 7) // 8, 'big')
