import asyncio
from PySIP.sip_account import SipAccount
from PySIP.sip_call import SipCall
from dotenv import load_dotenv
import os
import logging

load_dotenv()

# Enable detailed logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Patch SipCall message_handler to see what messages we're getting
import PySIP.sip_call
original_message_handler = PySIP.sip_call.SipCall.message_handler

async def debug_message_handler(self, msg):
    if msg.call_id == self.call_id:
        print(f'\n=== SipCall.message_handler ===')
        print(f'  Method: {msg.method}')
        print(f'  Status: {msg.status}')
        print(f'  Call-ID: {msg.call_id}')
        print(f'  CSeq: {msg.cseq}')
        if msg.status:
            print(f'  Status Code: {msg.status.code}')
        print(f'  Has proxy_auth: {msg.proxy_auth}')
        print(f'  Has nonce: {msg.nonce is not None}')
        print(f'  Has realm: {msg.realm is not None}')
    return await original_message_handler(self, msg)

PySIP.sip_call.SipCall.message_handler = debug_message_handler

account = SipAccount(
    os.environ["SIP_USERNAME"],
    os.environ["SIP_PASSWORD"],
    os.environ["SIP_SERVER"],
    connection_type="UDP",
)

@account.on_incoming_call
async def handle_incoming_call(call: SipCall):
    await call.accept()

async def main():
    print("Registering...")
    await account.register()
    print("Registered!\n")
    
    print("Making call...")
    call = account.make_call("16822625850")
    
    @call.on_call_state_changed
    async def on_state_change(state):
        print(f"\n>>> Call state: {state}")
    
    call_task = asyncio.create_task(call.start())
    
    # Wait 20 seconds to see what happens
    await asyncio.sleep(20)
    
    print("\nStopping call...")
    await call.stop()
    await call_task
    
    await account.unregister()

if __name__ == "__main__":
    asyncio.run(main())
