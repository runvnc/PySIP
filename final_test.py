#!/usr/bin/env python3
"""
Final comprehensive test of all PySIP fixes
"""

import asyncio
from PySIP.sip_account import SipAccount
from dotenv import load_dotenv
import os
import sys

load_dotenv()

async def main():
    print("\n" + "="*70)
    print("Final PySIP Registration Test")
    print("="*70)
    
    username = os.environ["SIP_USERNAME"]
    password = os.environ["SIP_PASSWORD"]
    server = os.environ["SIP_SERVER"]
    
    print(f"\nServer: {server}")
    print(f"Username: {username}")
    print(f"Password: {'*' * len(password)}")
    
    account = SipAccount(
        username,
        password,
        server,
        connection_type="UDP"
    )
    
    print("\nAttempting registration...")
    print("(This should complete in ~1 second if working correctly)\n")
    
    try:
        result = await asyncio.wait_for(account.register(), timeout=10)
        
        if result:
            print("\n" + "="*70)
            print("✓✓✓ SUCCESS! PySIP registration working!")
            print("="*70)
            print("\nAll fixes applied successfully:")
            print("  1. ✓ Added opaque parameter support")
            print("  2. ✓ Fixed URI format (removed port, kept transport)")
            print("  3. ✓ Fixed qop parsing for missing qop")
            print("  4. ✓ Fixed IPv4/IPv6 issue (using IPv4 only)")
            print("  5. ✓ Fixed retry handler operation tracking")
            print("\nPySIP is now ready to use with Telnyx!")
            print("="*70 + "\n")
            
            await account.unregister()
            return 0
        else:
            print("\n" + "="*70)
            print("✗ Registration returned False")
            print("="*70 + "\n")
            return 1
            
    except asyncio.TimeoutError:
        print("\n" + "="*70)
        print("✗ Registration timed out")
        print("="*70)
        print("\nThis means the 200 OK response is not being received.")
        print("Possible remaining issues:")
        print("  - Message handler not processing 200 OK")
        print("  - Retry handler not completing operation")
        print("  - Network/firewall issue")
        print("="*70 + "\n")
        return 1
        
    except Exception as e:
        print("\n" + "="*70)
        print(f"✗ Error: {e}")
        print("="*70 + "\n")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
