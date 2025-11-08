import asyncio
from PySIP.sip_account import SipAccount
import os
from dotenv import load_dotenv

load_dotenv()

account = SipAccount(os.environ['SIP_USERNAME'], os.environ['SIP_PASSWORD'], os.environ['SIP_SERVER'], connection_type='UDP')

@account.on_incoming_call
async def handle_incoming_call(call):
    await call.accept()

async def main():
    print('Step 1: Registering...')
    await account.register()
    print('Step 1: Registration complete!')
    
    print('\nStep 2: Creating call...')
    call = account.make_call("16822625850")
    print(f'Step 2: Call created, sip_core has {len(call.sip_core.on_message_callbacks)} callbacks')
    for i, cb in enumerate(call.sip_core.on_message_callbacks):
        print(f'  Callback {i}: {cb.__qualname__}')
    
    print('\nStep 3: Starting call...')
    call_task = asyncio.create_task(call.start())
    
    # Wait a bit to see what happens
    await asyncio.sleep(10)
    
    print('\nStep 4: Stopping...')
    await call.stop()
    await call_task
    await account.unregister()

if __name__ == "__main__":
    asyncio.run(main())
