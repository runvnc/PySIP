# Debug script to see what Telnyx actually sends
import re

auth_header = 'Digest realm="sip.telnyx.com", nonce="aQ6g0GkOn6RjtRiwa5o7Z5XX0v1TsLrdZdwIGkA=", opaque="2/10.13.246.184"'

print("Auth header:", auth_header)
print()

# Try to extract qop
try:
    qop = auth_header.split("qop=")[1].split('"')[1]
    print(f"qop found: {qop}")
except IndexError:
    print("qop NOT found in header (this is the bug!)")
    print("The code crashes when qop is not present")

print()
print("Correct way to parse:")
qop_match = re.search(r'qop="?([^"\s,]+)"?', auth_header)
if qop_match:
    print(f"qop: {qop_match.group(1)}")
else:
    print("qop: None (not present in header)")
