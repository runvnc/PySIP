import socket
import hashlib
from dotenv import load_dotenv
import os

load_dotenv()

def test_plain_everywhere():
    """Test with plain username everywhere - maybe baresip does this"""
    
    server = "sip.telnyx.com"
    port = 5060
    
    username = "userjason43702"
    password = os.environ["SIP_PASSWORD"]
    
    print("Testing with plain username everywhere:")
    print(f"  Username: {username}")
    print(f"  (No @domain anywhere)")
    print()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    # Get local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    
    call_id = "plain-test-final"
    branch = "z9hG4bK-plain-final"
    tag = "plain-tag-final"
    
    # Initial REGISTER
    register_msg = (
        f"REGISTER sip:{server} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {local_ip}:5060;branch={branch};rport\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{username}@{server}>;tag={tag}\r\n"
        f"To: <sip:{username}@{server}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 REGISTER\r\n"
        f"Contact: <sip:{username}@{local_ip}:5060>\r\n"
        f"Expires: 3600\r\n"
        f"User-Agent: Test-Client\r\n"
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
        
        # Extract received and rport from Via header
        via_line = [line for line in response.split('\r\n') if line.startswith('Via:')][0]
        received_ip = via_line.split('received=')[1].split(';')[0]
        rport = via_line.split('rport=')[1].split(';')[0] if 'rport=' in via_line else '5060'
        
        print(f"Received 401")
        print(f"  Realm: {realm}")
        print(f"  Public IP: {received_ip}")
        print(f"  RPort: {rport}")
        
        # Generate digest with PLAIN username only
        uri = f"sip:{server}"
        A1 = f"{username}:{realm}:{password}"
        A1_hash = hashlib.md5(A1.encode()).hexdigest()
        A2 = f"REGISTER:{uri}"
        A2_hash = hashlib.md5(A2.encode()).hexdigest()
        response_hash = hashlib.md5(f"{A1_hash}:{nonce}:{A2_hash}".encode()).hexdigest()
        
        print(f"\nDigest calculation:")
        print(f"  A1: {username}:{realm}:[password]")
        print(f"  A1 hash: {A1_hash}")
        print(f"  Response: {response_hash}")
        
        # Authenticated REGISTER - use public IP and rport
        auth_register = (
            f"REGISTER sip:{server} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {received_ip}:{rport};branch={branch};rport\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:{username}@{server}>;tag={tag}\r\n"
            f"To: <sip:{username}@{server}>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: 2 REGISTER\r\n"
            f"Contact: <sip:{username}@{received_ip}:{rport}>\r\n"
            f"Expires: 3600\r\n"
            f'Authorization: Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{response_hash}", algorithm=MD5\r\n'
            f"User-Agent: Test-Client\r\n"
            f"Content-Length: 0\r\n\r\n"
        )
        
        print("\nStep 2: Sending authenticated REGISTER...")
        print("(Using public IP in Via and Contact)")
        sock.sendto(auth_register.encode(), (server, port))
        data, addr = sock.recvfrom(4096)
        response = data.decode()
        
        print(f"\nResponse:")
        print("="*70)
        print(response)
        print("="*70)
        
        if "200 OK" in response:
            print("\n✓✓✓ SUCCESS! Registration worked!")
            return True
        elif "401" in response:
            print("\n✗ Still 401 - credentials issue")
            return False
        elif "403" in response:
            print("\n✗ 403 - authentication passed but access denied")
            print("This might be an account configuration issue in Telnyx portal")
            return False
        else:
            print("\n? Unexpected response")
            return False
            
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        sock.close()

if __name__ == "__main__":
    test_plain_everywhere()
