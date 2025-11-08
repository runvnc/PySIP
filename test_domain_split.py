import socket
import hashlib
from dotenv import load_dotenv
import os

load_dotenv()

def test_domain_split():
    """
    Test with split domains:
    - Server: sip.telnyx.com (where we send the REGISTER)
    - Domain: telnyx.com (used in From/To/Contact headers)
    
    This matches the GitHub issue pattern:
    server="sbc.megafon.ru", domain="multifon.ru"
    """
    
    server = "sip.telnyx.com"  # The SIP server
    domain = "telnyx.com"      # The SIP domain (without 'sip.' prefix)
    port = 5060
    
    username = "userjason43702"
    password = os.environ["SIP_PASSWORD"]
    
    print("Testing with SPLIT server/domain:")
    print(f"  Server (REGISTER to): {server}")
    print(f"  Domain (From/To): {domain}")
    print(f"  Username: {username}")
    print()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    # Get local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    
    call_id = "domain-split-test"
    branch = "z9hG4bK-split-test"
    tag = "split-tag-test"
    
    # Initial REGISTER - send to SERVER but use DOMAIN in From/To
    register_msg = (
        f"REGISTER sip:{server} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {local_ip}:5060;branch={branch};rport\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{username}@{domain}>;tag={tag}\r\n"
        f"To: <sip:{username}@{domain}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 REGISTER\r\n"
        f"Contact: <sip:{username}@{local_ip}:5060>\r\n"
        f"Expires: 3600\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    
    print("Initial REGISTER message:")
    print("-" * 70)
    print(register_msg)
    print("-" * 70)
    
    try:
        print("\nStep 1: Sending initial REGISTER...")
        sock.sendto(register_msg.encode(), (server, port))
        data, addr = sock.recvfrom(4096)
        response = data.decode()
        
        if "401" not in response:
            print(f"Unexpected: {response[:200]}")
            return False
        
        nonce = response.split('nonce="')[1].split('"')[0]
        realm = response.split('realm="')[1].split('"')[0]
        
        print(f"Received 401")
        print(f"  Realm: {realm}")
        
        # Generate digest - use plain username
        uri = f"sip:{server}"
        A1 = f"{username}:{realm}:{password}"
        A1_hash = hashlib.md5(A1.encode()).hexdigest()
        A2 = f"REGISTER:{uri}"
        A2_hash = hashlib.md5(A2.encode()).hexdigest()
        response_hash = hashlib.md5(f"{A1_hash}:{nonce}:{A2_hash}".encode()).hexdigest()
        
        print(f"\nDigest:")
        print(f"  A1: {username}:{realm}:[password]")
        print(f"  Response: {response_hash}")
        
        # Authenticated REGISTER - still use DOMAIN in From/To
        auth_register = (
            f"REGISTER sip:{server} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {local_ip}:5060;branch={branch};rport\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:{username}@{domain}>;tag={tag}\r\n"
            f"To: <sip:{username}@{domain}>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: 2 REGISTER\r\n"
            f"Contact: <sip:{username}@{local_ip}:5060>\r\n"
            f"Expires: 3600\r\n"
            f'Authorization: Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{response_hash}", algorithm=MD5\r\n'
            f"Content-Length: 0\r\n\r\n"
        )
        
        print("\nAuthenticated REGISTER message:")
        print("-" * 70)
        print(auth_register)
        print("-" * 70)
        
        print("\nStep 2: Sending authenticated REGISTER...")
        sock.sendto(auth_register.encode(), (server, port))
        data, addr = sock.recvfrom(4096)
        response = data.decode()
        
        print(f"\nResponse:")
        print("=" * 70)
        print(response)
        print("=" * 70)
        
        if "200 OK" in response:
            print("\n✓✓✓ SUCCESS! The domain split was the key!")
            print(f"\nSolution:")
            print(f"  - REGISTER to: sip:{server}")
            print(f"  - From/To domain: {domain}")
            print(f"  - Username: {username}")
            return True
        elif "401" in response:
            print("\n✗ Still 401 - not the domain split issue")
            return False
        elif "403" in response:
            print("\n✗ 403 - authentication passed but access denied")
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
    test_domain_split()
