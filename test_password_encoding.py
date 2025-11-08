import hashlib
import urllib.parse
from dotenv import load_dotenv
import os

load_dotenv()

password = os.environ["SIP_PASSWORD"]
username = os.environ["SIP_USERNAME"]
realm = "sip.telnyx.com"
uri = "sip:sip.telnyx.com"
nonce = "test_nonce_123"

print("Password from .env:", password)
print("Password bytes:", password.encode())
print("Password length:", len(password))
print()

# Test different ways of handling the password
print("Testing different password encodings:")
print("="*60)

# Method 1: Direct
A1_direct = f"{username}:{realm}:{password}"
A1_hash_direct = hashlib.md5(A1_direct.encode()).hexdigest()
print(f"Method 1 (direct): {A1_hash_direct}")

# Method 2: URL encoded
password_encoded = urllib.parse.quote(password)
A1_encoded = f"{username}:{realm}:{password_encoded}"
A1_hash_encoded = hashlib.md5(A1_encoded.encode()).hexdigest()
print(f"Method 2 (URL encoded): {A1_hash_encoded}")

# Method 3: Check if there are any hidden characters
print(f"\nPassword character analysis:")
for i, char in enumerate(password):
    print(f"  Position {i}: '{char}' (ASCII {ord(char)})")

print("\n" + "="*60)
print("If the password contains special characters like ^, !, ?, etc.")
print("they should be used as-is in the digest calculation (Method 1).")
print("URL encoding is NOT used for SIP digest authentication.")
