import asyncio
import socket
from dotenv import load_dotenv
import os

load_dotenv()

async def test_udp_connection():
    """Test basic UDP connectivity to Telnyx"""
    server = os.environ["SIP_SERVER"].split(":")[0]
    port = int(os.environ["SIP_SERVER"].split(":")[1])
    username = os.environ["SIP_USERNAME"]
    
    print(f"Testing UDP connection to {server}:{port}")
    
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    # Get local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    
    # Build simple REGISTER message
    call_id = "test-call-123"
    branch = "z9hG4bK-test-branch"
    tag = "test-tag-456"
    
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
    
    print("\n=== Sending REGISTER message ===")
    print(register_msg)
    print("================================\n")
    
    try:
        # Send REGISTER
        sock.sendto(register_msg.encode(), (server, port))
        print(f"Sent REGISTER to {server}:{port}")
        
        # Wait for response
        print("Waiting for response...")
        data, addr = sock.recvfrom(4096)
        
        print(f"\n=== Received response from {addr} ===")
        print(data.decode())
        print("====================================\n")
        
        return True
        
    except socket.timeout:
        print("ERROR: No response received (timeout)")
        print("\nPossible issues:")
        print("1. Firewall blocking UDP port 5060")
        print("2. Incorrect SIP credentials")
        print("3. Network connectivity issue")
        print("4. Telnyx requires credential authentication first")
        return False
        
    except Exception as e:
        print(f"ERROR: {e}")
        return False
        
    finally:
        sock.close()

if __name__ == "__main__":
    asyncio.run(test_udp_connection())
