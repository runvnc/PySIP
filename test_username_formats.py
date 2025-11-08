import asyncio
import socket
import hashlib
from dotenv import load_dotenv
import os

load_dotenv()

async def test_auth_with_username(username_format):
    """Test registration with different username formats"""
    server = os.environ["SIP_SERVER"].split(":")[0]
    port = int(os.environ["SIP_SERVER"].split(":")[1])
    base_username = os.environ["SIP_USERNAME"]
    password = os.environ["SIP_PASSWORD"]
    
    # Try different username formats
    if username_format == "plain":
        username = base_username
    elif username_format == "with_domain":
        username = f"{base_username}@{server}"
    else:
        username = base_username
    
    print(f"\n{'='*60}")
    print(f"Testing with username format: {username_format}")
    print(f"Username: {username}")
    print(f"{'='*60}")
    
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    # Get local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    
    # Build simple REGISTER message
    call_id = f"test-{username_format}-123"
    branch = f"z9hG4bK-{username_format}-branch"
    tag = f"tag-{username_format}-456"
    
    register_msg = (
        f"REGISTER sip:{server} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {local_ip}:5060;branch={branch};rport\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{base_username}@{server}>;tag={tag}\r\n"
        f"To: <sip:{base_username}@{server}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 REGISTER\r\n"
        f"Contact: <sip:{base_username}@{local_ip}:5060>\r\n"
        f"Expires: 600\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    
    try:
        # Send initial REGISTER
        print("\nStep 1: Sending initial REGISTER...")
        sock.sendto(register_msg.encode(), (server, port))
        
        # Wait for 401 response
        data, addr = sock.recvfrom(4096)
        response = data.decode()
        
        if "401" not in response:
            print(f"Unexpected response: {response[:100]}")
            return False
        
        # Parse nonce and realm
        nonce = response.split('nonce="')[1].split('"')[0]
        realm = response.split('realm="')[1].split('"')[0]
        
        print(f"Received 401, extracted realm: {realm}")
        
        # Generate digest response with the username format being tested
        uri = f"sip:{server}"
        A1 = f"{username}:{realm}:{password}"
        A1_hash = hashlib.md5(A1.encode()).hexdigest()
        A2 = f"REGISTER:{uri}"
        A2_hash = hashlib.md5(A2.encode()).hexdigest()
        response_hash = hashlib.md5(f"{A1_hash}:{nonce}:{A2_hash}".encode()).hexdigest()
        
        # Build authenticated REGISTER
        auth_register = (
            f"REGISTER sip:{server} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {local_ip}:5060;branch={branch};rport\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:{base_username}@{server}>;tag={tag}\r\n"
            f"To: <sip:{base_username}@{server}>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: 2 REGISTER\r\n"
            f"Contact: <sip:{base_username}@{local_ip}:5060>\r\n"
            f"Expires: 600\r\n"
            f'Authorization: Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{response_hash}", algorithm="MD5"\r\n'
            f"Content-Length: 0\r\n\r\n"
        )
        
        print("\nStep 2: Sending authenticated REGISTER...")
        sock.sendto(auth_register.encode(), (server, port))
        
        # Wait for response
        data, addr = sock.recvfrom(4096)
        response = data.decode()
        
        if "200 OK" in response:
            print(f"\n✓ SUCCESS with username format: {username_format}")
            print(f"  Username used: {username}")
            return True
        elif "401" in response:
            print(f"\n✗ FAILED: Still got 401 with username format: {username_format}")
            return False
        else:
            print(f"\n? UNEXPECTED: {response[:200]}")
            return False
        
    except socket.timeout:
        print(f"\n✗ TIMEOUT with username format: {username_format}")
        return False
        
    except Exception as e:
        print(f"\n✗ ERROR with username format {username_format}: {e}")
        return False
        
    finally:
        sock.close()

async def main():
    print("Testing different username formats for Telnyx authentication...\n")
    
    formats = ["plain", "with_domain"]
    
    for fmt in formats:
        result = await test_auth_with_username(fmt)
        if result:
            print(f"\n{'='*60}")
            print(f"FOUND WORKING FORMAT: {fmt}")
            print(f"{'='*60}")
            break
        await asyncio.sleep(1)  # Small delay between attempts
    else:
        print("\n" + "="*60)
        print("NONE OF THE USERNAME FORMATS WORKED")
        print("This suggests the credentials may be invalid or inactive.")
        print("Please verify in your Telnyx portal that:")
        print("  1. The SIP connection exists and is active")
        print("  2. The username and password are correct")
        print("  3. The connection type is set to 'Credentials'")
        print("="*60)

if __name__ == "__main__":
    asyncio.run(main())
