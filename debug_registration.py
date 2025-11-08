#!/usr/bin/env python3
"""
Debug registration to see all SIP messages
"""

import asyncio
import logging
from PySIP.sip_account import SipAccount
from PySIP.sip_core import SipMessage
from dotenv import load_dotenv
import os

load_dotenv()

# Set up detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

async def main():
    username = os.environ["SIP_USERNAME"]
    password = os.environ["SIP_PASSWORD"]
    server = os.environ["SIP_SERVER"]
    
    print(f"\n{'='*70}")
    print(f"Debug Registration Test")
    print(f"Server: {server}")
    print(f"Username: {username}")
    print(f"{'='*70}\n")
    
    account = SipAccount(
        username,
        password,
        server,
        connection_type="UDP"
    )
    
    # Add a message logger to see all SIP messages
    message_count = {'sent': 0, 'received': 0}
    
    async def log_all_messages(msg: SipMessage):
        message_count['received'] += 1
        print(f"\n{'='*70}")
        print(f"MESSAGE #{message_count['received']} RECEIVED:")
        print(f"{'='*70}")
        print(f"Type: {msg.type}")
        print(f"Method: {msg.method}")
        print(f"Status: {msg.status}")
        print(f"Call-ID: {msg.call_id}")
        print(f"CSeq: {msg.cseq}")
        print(f"From tag: {msg.from_tag}")
        print(f"To tag: {msg.to_tag}")
        if msg.status and msg.status.value == 401:
            print(f"Realm: {msg.realm}")
            print(f"Nonce: {msg.nonce[:30] if msg.nonce else None}...")
            print(f"Opaque: {msg.opaque}")
        print(f"\nFull message (first 500 chars):")
        print(msg.data[:500])
        print(f"{'='*70}\n")
    
    # Register the logger before starting
    print("Registering message logger...")
    
    try:
        print("\nAttempting registration...\n")
        result = await asyncio.wait_for(account.register(), timeout=15)
        
        if result:
            print(f"\n{'='*70}")
            print("✓✓✓ REGISTRATION SUCCESSFUL!")
            print(f"{'='*70}\n")
        else:
            print(f"\n{'='*70}")
            print("✗ REGISTRATION FAILED")
            print(f"{'='*70}\n")
            
    except asyncio.TimeoutError:
        print(f"\n{'='*70}")
        print("✗ REGISTRATION TIMED OUT")
        print(f"{'='*70}\n")
    except Exception as e:
        print(f"\n{'='*70}")
        print(f"✗ ERROR: {e}")
        print(f"{'='*70}\n")
        import traceback
        traceback.print_exc()
    finally:
        print(f"\nMessages received: {message_count['received']}")
        await account.unregister()

if __name__ == "__main__":
    asyncio.run(main())
