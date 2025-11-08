import asyncio
from PySIP.sip_account import SipAccount
from PySIP.sip_call import SipCall
from dotenv import load_dotenv
import os
import logging

load_dotenv()

# Enable detailed logging
logging.basicConfig(level=logging.INFO)

# Patch to see error responses
import PySIP.sip_call
original_error_handler = PySIP.sip_call.SipCall.error_handler

async def debug_error_handler(self, msg):
    if msg.call_id == self.call_id and msg.status:
        print(f'\n=== ERROR RESPONSE ===')
        print(f'  Status: {msg.status} ({msg.status.code})')
        print(f'  Method: {msg.method}')
        print(f'  Message: {msg.status.phrase if msg.status else "N/A"}')
    return await original_error_handler(self, msg)

PySIP.sip_call.SipCall.error_handler = debug_error_handler

account = SipAccount(
    os.environ["SIP_USERNAME"],
    os.environ["SIP_PASSWORD"],
    os.environ["SIP_SERVER"],
    connection_type="UDP",
)

async def main():
    print("Registering...")
    await account.register()
    print("Registered!\n")
    
    print("Making call to 16822625850...")
    call = account.make_call("16822625850")
    
    @call.on_call_state_changed
    async def on_state_change(state):
        print(f"Call state: {state}")
    
    call_task = asyncio.create_task(call.start())
    
    # Wait 10 seconds
    await asyncio.sleep(10)
    
    print("\nStopping...")
    await call.stop()
    await call_task
    await account.unregister()

if __name__ == "__main__":
    asyncio.run(main())
