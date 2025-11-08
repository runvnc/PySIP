import socket
import hashlib
from dotenv import load_dotenv
import os

load_dotenv()

def test_with_baresip_format():
    """Test using the exact format from baresip config"""
    
    # Baresip uses: sip:userjason43702@sip.telnyx.com
    # So the username part is: userjason43702@sip.telnyx.com
    # And we register to server: sip.telnyx.com
    
    server = "sip.telnyx.com"
    port = 5060
    
    # Try with full user@domain as username in digest
    username_for_digest = "userjason43702@sip.telnyx.com"
    username_display = "userjason43702"  # For From/To headers
    password = os.environ["SIP_PASSWORD"]
    
    print("Testing with baresip-style format:")
    print(f"  Username in digest: {username_for_digest}")
    print(f"  Username in headers: {username_display}")
    print()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    # Get local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    
    call_id = "baresip-format-test"
    branch = "z9hG4bK-baresip-test"
    tag = "baresip-tag-test"
    
    # Initial REGISTER
    register_msg = (
        f"REGISTER sip:{server} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {local_ip}:5060;branch={branch};rport\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{username_display}@{server}>;tag={tag}\r\n"
        f"To: <sip:{username_display}@{server}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 REGISTER\r\n"
        f"Contact: <sip:{username_display}@{local_ip}:5060>\r\n"
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
        
        # Generate digest with FULL username including domain
        uri = f"sip:{server}"
        A1 = f"{username_for_digest}:{realm}:{password}"
        A1_hash = hashlib.md5(A1.encode()).hexdigest()
        A2 = f"REGISTER:{uri}"
        A2_hash = hashlib.md5(A2.encode()).hexdigest()
        response_hash = hashlib.md5(f"{A1_hash}:{nonce}:{A2_hash}".encode()).hexdigest()
        
        print(f"\nDigest A1: {username_for_digest}:{realm}:[password]")
        print(f"Response hash: {response_hash}")
        
        # Authenticated REGISTER with full username in Authorization
        auth_register = (
            f"REGISTER sip:{server} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {local_ip}:5060;branch={branch};rport\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:{username_display}@{server}>;tag={tag}\r\n"
            f"To: <sip:{username_display}@{server}>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: 2 REGISTER\r\n"
            f"Contact: <sip:{username_display}@{local_ip}:5060>\r\n"
            f"Expires: 600\r\n"
            f'Authorization: Digest username="{username_for_digest}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{response_hash}", algorithm="MD5"\r\n'
            f"Content-Length: 0\r\n\r\n"
        )
        
        print("\nStep 2: Sending authenticated REGISTER...")
        sock.sendto(auth_register.encode(), (server, port))
        data, addr = sock.recvfrom(4096)
        response = data.decode()
        
        print(f"\nResponse:")
        print(response)
        
        if "200 OK" in response:
            print("\n\u2713\u2713\u2713 SUCCESS! This is the correct format!")
            return True
        else:
            print("\n✗ Still failed")
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        sock.close()

if __name__ == "__main__":
    test_with_baresip_format()
