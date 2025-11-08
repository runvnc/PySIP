import socket
import hashlib
from dotenv import load_dotenv
import os

load_dotenv()

def test_with_opaque_and_transport():
    """Test with opaque parameter and transport in URI"""
    
    server = "sip.telnyx.com"
    port = 5060
    username = "userjason43702"
    password = os.environ["SIP_PASSWORD"]
    
    print("Testing with OPAQUE and transport=udp in URI")
    print(f"  Username: {username}")
    print()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    # Get local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    local_port = 5060
    s.close()
    
    call_id = "opaque-test-final"
    branch = "z9hG4bK-opaque-test"
    tag = "opaque-tag-test"
    
    # Initial REGISTER
    register_msg = (
        f"REGISTER sip:{server};transport=udp SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch};rport\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{username}@{server}>;tag={tag}\r\n"
        f"To: <sip:{username}@{server}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 REGISTER\r\n"
        f"Contact: <sip:{username}@{local_ip}:{local_port}>\r\n"
        f"Expires: 3600\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    
    try:
        print("Step 1: Sending initial REGISTER...")
        sock.sendto(register_msg.encode(), (server, port))
        data, addr = sock.recvfrom(4096)
        response = data.decode()
        
        if "401" not in response:
            print(f"Unexpected: {response[:200]}")
            return False
        
        # Parse authentication parameters including opaque
        nonce = response.split('nonce="')[1].split('"')[0]
        realm = response.split('realm="')[1].split('"')[0]
        
        # Extract opaque if present
        opaque = None
        if 'opaque="' in response:
            opaque = response.split('opaque="')[1].split('"')[0]
        
        print(f"Received 401")
        print(f"  Realm: {realm}")
        print(f"  Nonce: {nonce[:30]}...")
        print(f"  Opaque: {opaque}")
        
        # Generate digest - URI must include transport!
        uri = f"sip:{server};transport=udp"
        A1 = f"{username}:{realm}:{password}"
        A1_hash = hashlib.md5(A1.encode()).hexdigest()
        A2 = f"REGISTER:{uri}"
        A2_hash = hashlib.md5(A2.encode()).hexdigest()
        response_hash = hashlib.md5(f"{A1_hash}:{nonce}:{A2_hash}".encode()).hexdigest()
        
        print(f"\nDigest calculation:")
        print(f"  A1: {username}:{realm}:[password]")
        print(f"  A2: REGISTER:{uri}")
        print(f"  Response: {response_hash}")
        
        # Build Authorization header with opaque
        auth_header = (
            f'Authorization: Digest username="{username}", '
            f'realm="{realm}", '
            f'nonce="{nonce}", '
            f'uri="{uri}", '
            f'response="{response_hash}"'
        )
        
        if opaque:
            auth_header += f', opaque="{opaque}"'
        
        auth_header += "\r\n"
        
        # Authenticated REGISTER
        auth_register = (
            f"REGISTER sip:{server};transport=udp SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch};rport\r\n"
            f"Max-Forwards: 70\r\n"
            f"{auth_header}"
            f"From: <sip:{username}@{server}>;tag={tag}\r\n"
            f"To: <sip:{username}@{server}>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: 2 REGISTER\r\n"
            f"Contact: <sip:{username}@{local_ip}:{local_port}>\r\n"
            f"Expires: 3600\r\n"
            f"Content-Length: 0\r\n\r\n"
        )
        
        print("\nStep 2: Sending authenticated REGISTER...")
        print("(With opaque and transport=udp in URI)")
        sock.sendto(auth_register.encode(), (server, port))
        data, addr = sock.recvfrom(4096)
        response = data.decode()
        
        print(f"\nResponse:")
        print("=" * 70)
        print(response)
        print("=" * 70)
        
        if "200 OK" in response:
            print("\n✓✓✓ SUCCESS! Registration worked!")
            print("\nThe missing pieces were:")
            print("  1. Include 'opaque' parameter in Authorization header")
            print("  2. Use 'sip:sip.telnyx.com;transport=udp' as the URI")
            return True
        elif "401" in response:
            print("\n✗ Still 401")
            return False
        elif "403" in response:
            print("\n✗ 403")
            return False
        else:
            print("\n? Unexpected")
            return False
            
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        sock.close()

if __name__ == "__main__":
    test_with_opaque_and_transport()
