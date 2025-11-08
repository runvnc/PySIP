#!/usr/bin/env python3
"""
Comprehensive Telnyx SIP Registration Diagnostic Tool
"""

import socket
import hashlib
from dotenv import load_dotenv
import os
import sys

load_dotenv()

def test_connectivity():
    """Test basic network connectivity to Telnyx"""
    print("\n" + "="*70)
    print("TEST 1: Network Connectivity")
    print("="*70)
    
    server = "sip.telnyx.com"
    port = 5060
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(b"test", (server, port))
        print(f"✓ Can reach {server}:{port}")
        sock.close()
        return True
    except Exception as e:
        print(f"✗ Cannot reach {server}:{port}")
        print(f"  Error: {e}")
        return False

def test_initial_register():
    """Test if we get a 401 response"""
    print("\n" + "="*70)
    print("TEST 2: Initial REGISTER (expecting 401 Unauthorized)")
    print("="*70)
    
    server = "sip.telnyx.com"
    port = 5060
    username = os.environ.get("SIP_USERNAME")
    
    if not username:
        print("✗ SIP_USERNAME not found in .env file")
        return None
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    # Get local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    
    call_id = "diagnostic-test-001"
    branch = "z9hG4bK-diagnostic-001"
    tag = "diagnostic-tag-001"
    
    register_msg = (
        f"REGISTER sip:{server} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {local_ip}:5060;branch={branch};rport\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{username}@{server}>;tag={tag}\r\n"
        f"To: <sip:{username}@{server}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 REGISTER\r\n"
        f"Contact: <sip:{username}@{local_ip}:5060>\r\n"
        f"Expires: 600\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    
    try:
        sock.sendto(register_msg.encode(), (server, port))
        data, addr = sock.recvfrom(4096)
        response = data.decode()
        
        if "401" in response:
            print("✓ Received 401 Unauthorized (expected)")
            
            # Extract auth parameters
            try:
                nonce = response.split('nonce="')[1].split('"')[0]
                realm = response.split('realm="')[1].split('"')[0]
                print(f"  Realm: {realm}")
                print(f"  Nonce: {nonce[:20]}...")
                sock.close()
                return {"nonce": nonce, "realm": realm, "response": response}
            except:
                print("✗ Could not parse authentication parameters")
                print(f"  Response: {response[:200]}")
                sock.close()
                return None
        else:
            print(f"✗ Unexpected response: {response[:100]}")
            sock.close()
            return None
            
    except socket.timeout:
        print("✗ Timeout - no response from server")
        sock.close()
        return None
    except Exception as e:
        print(f"✗ Error: {e}")
        sock.close()
        return None

def test_authenticated_register(auth_info):
    """Test authenticated REGISTER"""
    print("\n" + "="*70)
    print("TEST 3: Authenticated REGISTER (expecting 200 OK or specific error)")
    print("="*70)
    
    server = "sip.telnyx.com"
    port = 5060
    username = os.environ.get("SIP_USERNAME")
    password = os.environ.get("SIP_PASSWORD")
    
    if not username or not password:
        print("✗ Credentials not found in .env file")
        return False
    
    print(f"Username: {username}")
    print(f"Password: {'*' * len(password)} (length: {len(password)})")
    
    nonce = auth_info["nonce"]
    realm = auth_info["realm"]
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    # Get local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    
    call_id = "diagnostic-test-001"
    branch = "z9hG4bK-diagnostic-001"
    tag = "diagnostic-tag-001"
    
    # Generate digest response
    uri = f"sip:{server}"
    A1 = f"{username}:{realm}:{password}"
    A1_hash = hashlib.md5(A1.encode()).hexdigest()
    A2 = f"REGISTER:{uri}"
    A2_hash = hashlib.md5(A2.encode()).hexdigest()
    response_hash = hashlib.md5(f"{A1_hash}:{nonce}:{A2_hash}".encode()).hexdigest()
    
    print(f"\nDigest calculation:")
    print(f"  A1: {username}:{realm}:[password]")
    print(f"  A1 hash: {A1_hash}")
    print(f"  A2: REGISTER:{uri}")
    print(f"  A2 hash: {A2_hash}")
    print(f"  Response: {response_hash}")
    
    auth_register = (
        f"REGISTER sip:{server} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {local_ip}:5060;branch={branch};rport\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{username}@{server}>;tag={tag}\r\n"
        f"To: <sip:{username}@{server}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 2 REGISTER\r\n"
        f"Contact: <sip:{username}@{local_ip}:5060>\r\n"
        f"Expires: 600\r\n"
        f'Authorization: Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{response_hash}", algorithm="MD5"\r\n'
        f"Content-Length: 0\r\n\r\n"
    )
    
    try:
        sock.sendto(auth_register.encode(), (server, port))
        data, addr = sock.recvfrom(4096)
        response = data.decode()
        
        print(f"\nResponse received:")
        print("-" * 70)
        print(response)
        print("-" * 70)
        
        if "200 OK" in response:
            print("\n✓✓✓ SUCCESS! Registration completed!")
            sock.close()
            return True
        elif "401" in response:
            print("\n✗ Still getting 401 Unauthorized")
            print("\nPossible causes:")
            print("  1. Username or password is incorrect")
            print("  2. SIP connection is not active in Telnyx portal")
            print("  3. SIP connection is not set to 'Credentials' auth type")
            print("  4. The credentials were recently changed and not updated in .env")
            sock.close()
            return False
        elif "403" in response:
            print("\n✗ 403 Forbidden")
            print("  The credentials may be correct but access is denied")
            print("  Check if the SIP connection is enabled in Telnyx portal")
            sock.close()
            return False
        else:
            print(f"\n✗ Unexpected response")
            sock.close()
            return False
            
    except socket.timeout:
        print("\n✗ Timeout - no response from server")
        print("  This could indicate a firewall issue")
        sock.close()
        return False
    except Exception as e:
        print(f"\n✗ Error: {e}")
        sock.close()
        return False

def main():
    print("\n" + "#"*70)
    print("#" + " "*68 + "#")
    print("#" + "  Telnyx SIP Registration Diagnostic Tool".center(68) + "#")
    print("#" + " "*68 + "#")
    print("#"*70)
    
    # Check .env file
    if not os.path.exists(".env"):
        print("\n✗ ERROR: .env file not found")
        sys.exit(1)
    
    username = os.environ.get("SIP_USERNAME")
    password = os.environ.get("SIP_PASSWORD")
    server = os.environ.get("SIP_SERVER")
    
    print("\nConfiguration:")
    print(f"  SIP_SERVER: {server}")
    print(f"  SIP_USERNAME: {username}")
    print(f"  SIP_PASSWORD: {'*' * len(password) if password else 'NOT SET'}")
    
    if not all([username, password, server]):
        print("\n✗ ERROR: Missing credentials in .env file")
        sys.exit(1)
    
    # Run tests
    if not test_connectivity():
        print("\n✗ FAILED: Cannot reach Telnyx server")
        sys.exit(1)
    
    auth_info = test_initial_register()
    if not auth_info:
        print("\n✗ FAILED: Could not get authentication challenge")
        sys.exit(1)
    
    success = test_authenticated_register(auth_info)
    
    print("\n" + "="*70)
    if success:
        print("RESULT: ✓ All tests passed! Your credentials are working.")
        print("\nThe PySIP library should work now with the bug fix applied.")
    else:
        print("RESULT: ✗ Authentication failed")
        print("\nNext steps:")
        print("  1. Log into https://portal.telnyx.com")
        print("  2. Go to Voice → SIP Connections")
        print("  3. Find or create a connection with 'Credentials' auth")
        print("  4. Verify the username and password match your .env file")
        print("  5. Ensure the connection is Active (not disabled)")
    print("="*70 + "\n")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
