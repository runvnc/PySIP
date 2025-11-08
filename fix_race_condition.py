"""Test fix for race condition between receive_task and register"""
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
    print('Registering...')
    await account.register()
    print('Registration complete!')
    
    # Give receive task time to start
    print('Waiting for receive task to be ready...')
    if account._SipAccount__sip_client:
        # Wait for receive task to actually be running
        await asyncio.sleep(0.5)
        print(f'Receive task exists: {account._SipAccount__sip_client.sip_core.receive_task is not None}')
        print(f'Is running: {account._SipAccount__sip_client.sip_core.is_running.is_set()}')
    
    await account.unregister()

if __name__ == "__main__":
    asyncio.run(main())
