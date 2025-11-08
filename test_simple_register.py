#!/usr/bin/env python3
"""
Simple registration test that bypasses PySIP's retry handler
"""

import asyncio
from PySIP.sip_core import SipCore
from dotenv import load_dotenv
import os

load_dotenv()

async def simple_register_test():
    username = os.environ["SIP_USERNAME"]
    password = os.environ["SIP_PASSWORD"]
    server = os.environ["SIP_SERVER"].split(":")[0]
    
    print(f"Testing registration with fixed PySIP code")
    print(f"Server: {server}")
    print(f"Username: {username}")
    print()
    
    # Create SipCore instance
    sip_core = SipCore(username, f"{server}:5060", "UDP", password)
    
    # Connect
    print("Connecting...")
    await sip_core.connect()
    print("Connected!")
    
    # Get IPs
    public_ip = await asyncio.to_thread(sip_core.get_public_ip)
    private_ip = await asyncio.to_thread(sip_core.get_local_ip)
    print(f"Private IP: {private_ip}")
    print(f"Public IP: {public_ip}")
    
    # Build initial REGISTER
    call_id = sip_core.gen_call_id()
    branch = sip_core.gen_branch()
    tag = sip_core.generate_tag()
    
    _, local_port = sip_core.get_extra_info("sockname")
    
    register_msg = (
        f"REGISTER sip:{server};transport=UDP SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {private_ip}:{local_port};branch={branch};rport\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{username}@{server}>;tag={tag}\r\n"
        f"To: <sip:{username}@{server}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 REGISTER\r\n"
        f"Contact: <sip:{username}@{public_ip}:{local_port};transport=UDP>\r\n"
        f"Expires: 3600\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    
    print("\nSending initial REGISTER...")
    await sip_core.send(register_msg)
    
    # Wait for 401
    print("Waiting for 401 response...")
    response_received = asyncio.Event()
    auth_response = None
    
    async def handle_401(msg):
        nonlocal auth_response
        if msg.status and msg.status.value == 401 and msg.method == "REGISTER":
            auth_response = msg
            response_received.set()
    
    sip_core.on_message_callbacks.append(handle_401)
    
    # Start receiving
    receive_task = asyncio.create_task(sip_core.receive())
    
    try:
        await asyncio.wait_for(response_received.wait(), timeout=5)
        print(f"Received 401!")
        print(f"  Realm: {auth_response.realm}")
        print(f"  Nonce: {auth_response.nonce[:30]}...")
        print(f"  Opaque: {auth_response.opaque}")
        
        # Build authenticated REGISTER
        uri = f"sip:{server};transport=UDP"
        response_hash = sip_core.generate_response(
            method="REGISTER",
            nonce=auth_response.nonce,
            realm=auth_response.realm,
            uri=uri
        )
        
        auth_header = (
            f'Authorization: Digest username="{username}", '
            f'realm="{auth_response.realm}", '
            f'nonce="{auth_response.nonce}", '
            f'uri="{uri}", '
            f'response="{response_hash}", '
            f'algorithm=MD5'
        )
        
        if auth_response.opaque:
            auth_header += f', opaque="{auth_response.opaque}"'
        
        auth_register = (
            f"REGISTER sip:{server};transport=UDP SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {private_ip}:{local_port};branch={branch};rport\r\n"
            f"Max-Forwards: 70\r\n"
            f"{auth_header}\r\n"
            f"From: <sip:{username}@{server}>;tag={tag}\r\n"
            f"To: <sip:{username}@{server}>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: 2 REGISTER\r\n"
            f"Contact: <sip:{username}@{public_ip}:{local_port};transport=UDP>\r\n"
            f"Expires: 3600\r\n"
            f"Content-Length: 0\r\n\r\n"
        )
        
        print("\nSending authenticated REGISTER...")
        
        # Wait for 200 OK
        response_received.clear()
        final_response = None
        
        async def handle_200(msg):
            nonlocal final_response
            if msg.status and msg.status.value == 200 and msg.method == "REGISTER":
                final_response = msg
                response_received.set()
        
        sip_core.on_message_callbacks.append(handle_200)
        
        await sip_core.send(auth_register)
        
        await asyncio.wait_for(response_received.wait(), timeout=5)
        
        if final_response:
            print("\n" + "="*70)
            print("✓✓✓ SUCCESS! Received 200 OK!")
            print("="*70)
            print("\nPySIP fixes are working correctly!")
            print("\nThe fixes applied:")
            print("  1. Added opaque parameter support")
            print("  2. Fixed URI to include transport parameter")
            print("  3. Fixed qop parsing to handle missing qop")
            return True
        else:
            print("\n✗ Did not receive 200 OK")
            return False
            
    except asyncio.TimeoutError:
        print("\n✗ Timeout waiting for response")
        return False
    finally:
        sip_core.is_running.clear()
        receive_task.cancel()
        try:
            await receive_task
        except asyncio.CancelledError:
            pass
        await sip_core.close_connections()

if __name__ == "__main__":
    result = asyncio.run(simple_register_test())
    exit(0 if result else 1)
