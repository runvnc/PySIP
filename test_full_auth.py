import asyncio
import socket
import hashlib
from dotenv import load_dotenv
import os

load_dotenv()

async def test_full_registration():
    """Test full registration with digest authentication"""
    server = os.environ["SIP_SERVER"].split(":")[0]
    port = int(os.environ["SIP_SERVER"].split(":")[1])
    username = os.environ["SIP_USERNAME"]
    password = os.environ["SIP_PASSWORD"]
    
    print(f"Testing full registration to {server}:{port}")
    print(f"Username: {username}")
    
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    # Get local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    
    # Build simple REGISTER message
    call_id = "test-call-456"
    branch = "z9hG4bK-test-branch-2"
    tag = "test-tag-789"
    
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
        # Send initial REGISTER
        print("\n=== Step 1: Sending initial REGISTER ===")
        sock.sendto(register_msg.encode(), (server, port))
        
        # Wait for 401 response
        print("Waiting for 401 Unauthorized...")
        data, addr = sock.recvfrom(4096)
        response = data.decode()
        
        print(f"\n=== Received from {addr} ===")
        print(response)
        
        # Parse nonce and realm
        nonce = response.split('nonce="')[1].split('"')[0]
        realm = response.split('realm="')[1].split('"')[0]
        
        print(f"\nExtracted:")
        print(f"  Realm: {realm}")
        print(f"  Nonce: {nonce}")
        
        # Generate digest response
        uri = f"sip:{server}"
        A1 = f"{username}:{realm}:{password}"
        A1_hash = hashlib.md5(A1.encode()).hexdigest()
        A2 = f"REGISTER:{uri}"
        A2_hash = hashlib.md5(A2.encode()).hexdigest()
        response_hash = hashlib.md5(f"{A1_hash}:{nonce}:{A2_hash}".encode()).hexdigest()
        
        print(f"\nGenerated digest response: {response_hash}")
        
        # Build authenticated REGISTER
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
        
        print("\n=== Step 2: Sending authenticated REGISTER ===")
        print(auth_register)
        
        sock.sendto(auth_register.encode(), (server, port))
        
        # Wait for 200 OK
        print("Waiting for 200 OK...")
        data, addr = sock.recvfrom(4096)
        response = data.decode()
        
        print(f"\n=== Final response from {addr} ===")
        print(response)
        
        if "200 OK" in response:
            print("\n✓ SUCCESS! Registration completed!")
            return True
        else:
            print("\n✗ FAILED! Did not receive 200 OK")
            return False
        
    except socket.timeout:
        print("\n✗ ERROR: Timeout waiting for response")
        return False
        
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        sock.close()

if __name__ == "__main__":
    asyncio.run(test_full_registration())
