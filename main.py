from feal import FEAL
from cbc import CBC
from ec_elgamal import ECElGamal, EllipticCurve, Point
from schnorr_signature import SchnorrSignature

def print_separator():
    print("\n" + "-"*50 + "\n")

def main():
    # Setup elliptic curve (using secp256k1 parameters)
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    curve = EllipticCurve(
        p=p,
        a=0,
        b=7
    )
    
    # Generator point and its order
    G = Point(
        x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    )
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    print("Secure SMS Exchange System Demo")
    print_separator()

    # Initialize components
    print("1. Initializing cryptographic components...")
    feal = FEAL(key_size=64)  # Using 64-bit key for FEAL
    cbc = CBC(feal)
    ec_elgamal = ECElGamal(curve, G, n)
    schnorr = SchnorrSignature(curve, G, n)

    # Generate keys for both parties
    print("2. Generating keys for Alice and Bob...")
    # Alice's keys for EC-ElGamal and Schnorr
    alice_elgamal_private, alice_elgamal_public = ec_elgamal.generate_keypair()
    alice_schnorr_private, alice_schnorr_public = schnorr.generate_keypair()
    
    # Bob's keys for EC-ElGamal and Schnorr
    bob_elgamal_private, bob_elgamal_public = ec_elgamal.generate_keypair()
    bob_schnorr_private, bob_schnorr_public = schnorr.generate_keypair()
    
    print("   Keys generated successfully")
    print_separator()

    # Simulate SMS exchange from Alice to Bob
    print("3. Alice preparing to send SMS to Bob...")
    
    # Original SMS message
    sms_message = b"Hello Bob! This is a secure message from Alice."
    print(f"   Original message: {sms_message.decode()}")

    # Generate symmetric key for FEAL
    feal_key = b"SecretK1"  # 64-bit key
    print("   Generated FEAL symmetric key")

    # Alice encrypts FEAL key using Bob's EC-ElGamal public key
    print("4. Encrypting FEAL key using EC-ElGamal...")
    encoded_key = ec_elgamal.encode_message(feal_key)
    encrypted_key = ec_elgamal.encrypt(encoded_key, bob_elgamal_public)
    print("   FEAL key encrypted successfully")

    # Encrypt the SMS using FEAL in CBC mode
    print("5. Encrypting SMS using FEAL in CBC mode...")
    iv = cbc.generate_iv()
    encrypted_sms = cbc.encrypt(sms_message, feal_key, iv)
    print("   SMS encrypted successfully")

    # Alice signs the encrypted SMS
    print("6. Signing encrypted SMS using Schnorr signature...")
    signature = schnorr.sign(encrypted_sms, alice_schnorr_private)
    print("   Signature generated successfully")
    print_separator()

    # Bob receives and processes the message
    print("7. Bob receiving and verifying the message...")
    
    # Verify signature
    print("   Verifying Schnorr signature...")
    is_valid = schnorr.verify(encrypted_sms, signature, alice_schnorr_public)
    if not is_valid:
        print("   ERROR: Invalid signature!")
        return
    print("   Signature verified successfully")

    # Decrypt FEAL key
    print("8. Decrypting FEAL key using EC-ElGamal...")
    decrypted_key_point = ec_elgamal.decrypt(encrypted_key, bob_elgamal_private)
    decrypted_key = ec_elgamal.decode_message(decrypted_key_point)
    if decrypted_key != feal_key:
        print("   ERROR: Key decryption failed!")
        return
    print("   FEAL key decrypted successfully")

    # Decrypt SMS
    print("9. Decrypting SMS using FEAL in CBC mode...")
    decrypted_sms = cbc.decrypt(encrypted_sms, decrypted_key, iv)
    print("   SMS decrypted successfully")
    print_separator()

    # Show results
    print("Final Results:")
    print(f"Original SMS: {sms_message.decode()}")
    print(f"Decrypted SMS: {decrypted_sms.decode()}")
    print(f"Message integrity: {'✓' if sms_message == decrypted_sms else '✗'}")
    print_separator()

if __name__ == "__main__":
    main()