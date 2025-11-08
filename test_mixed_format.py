import socket
import hashlib
from dotenv import load_dotenv
import os

load_dotenv()

def test_mixed_format():
    """Test with plain username in Authorization but full username in digest"""
    
    server = "sip.telnyx.com"
    port = 5060
    
    username_plain = "userjason43702"
    username_full = "userjason43702@sip.telnyx.com"
    password = os.environ["SIP_PASSWORD"]
    
    print("Testing mixed format:")
    print(f"  Username in Authorization header: {username_plain}")
    print(f"  Username in digest calculation: {username_full}")
    print()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    # Get local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    
    call_id = "mixed-format-test"
    branch = "z9hG4bK-mixed-test"
    tag = "mixed-tag-test"
    
    # Initial REGISTER
    register_msg = (
        f"REGISTER sip:{server} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {local_ip}:5060;branch={branch};rport\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{username_plain}@{server}>;tag={tag}\r\n"
        f"To: <sip:{username_plain}@{server}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 REGISTER\r\n"
        f"Contact: <sip:{username_plain}@{local_ip}:5060>\r\n"
        f"Expires: 600\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    
    try:
        print("Step 1: Sending initial REGISTER...")
        sock.sendto(register_msg.encode(), (server, port))
        data, addr = sock.recvfrom(4096)
        response = data.decode()
        
        if "401" not in response:
            print(f"Unexpected: {response[:100]}")
            return False
        
        nonce = response.split('nonce="')[1].split('"')[0]
        realm = response.split('realm="')[1].split('"')[0]
        
        print(f"Received 401, realm: {realm}")
        
        # Generate digest with FULL username
        uri = f"sip:{server}"
        A1 = f"{username_full}:{realm}:{password}"
        A1_hash = hashlib.md5(A1.encode()).hexdigest()
        A2 = f"REGISTER:{uri}"
        A2_hash = hashlib.md5(A2.encode()).hexdigest()
        response_hash = hashlib.md5(f"{A1_hash}:{nonce}:{A2_hash}".encode()).hexdigest()
        
        print(f"\nDigest A1: {username_full}:{realm}:[password]")
        print(f"Response hash: {response_hash}")
        
        # Authenticated REGISTER with PLAIN username in Authorization header
        auth_register = (
            f"REGISTER sip:{server} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {local_ip}:5060;branch={branch};rport\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:{username_plain}@{server}>;tag={tag}\r\n"
            f"To: <sip:{username_plain}@{server}>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: 2 REGISTER\r\n"
            f"Contact: <sip:{username_plain}@{local_ip}:5060>\r\n"
            f"Expires: 600\r\n"
            f'Authorization: Digest username="{username_plain}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{response_hash}", algorithm="MD5"\r\n'
            f"Content-Length: 0\r\n\r\n"
        )
        
        print("\nStep 2: Sending authenticated REGISTER with plain username in header...")
        sock.sendto(auth_register.encode(), (server, port))
        data, addr = sock.recvfrom(4096)
        response = data.decode()
        
        print(f"\nResponse:")
        print(response)
        
        if "200 OK" in response:
            print("\n\u2713\u2713\u2713 SUCCESS! Found the right combination!")
            print("\nThe solution:")
            print(f"  - Use '{username_plain}' in Authorization header")
            print(f"  - Use '{username_full}' in digest calculation")
            return True
        else:
            print("\n✗ Still failed")
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        sock.close()

if __name__ == "__main__":
    success = test_mixed_format()
    if not success:
        print("\nTrying reverse: full username in header, plain in digest...")
        # Could add reverse test here if needed
