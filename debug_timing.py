"""Debug timing of receive task vs registration"""
import asyncio
from PySIP.sip_account import SipAccount
from PySIP.sip_client import SipClient
import os
from dotenv import load_dotenv
import time

load_dotenv()

# Patch to add timing logs
original_run = SipClient.run
async def debug_run(self):
    print(f'[{time.time():.3f}] SipClient.run() started')
    result = await original_run(self)
    print(f'[{time.time():.3f}] SipClient.run() finished')
    return result

SipClient.run = debug_run

original_register = SipClient.register
async def debug_register(self):
    print(f'[{time.time():.3f}] SipClient.register() called')
    print(f'[{time.time():.3f}] receive_task exists: {self.sip_core.receive_task is not None}')
    result = await original_register(self)
    print(f'[{time.time():.3f}] SipClient.register() finished: {result}')
    return result

SipClient.register = debug_register

import PySIP.sip_core
original_receive = PySIP.sip_core.SipCore.receive
async def debug_receive(self):
    print(f'[{time.time():.3f}] SipCore.receive() started')
    result = await original_receive(self)
    print(f'[{time.time():.3f}] SipCore.receive() finished')
    return result

PySIP.sip_core.SipCore.receive = debug_receive

account = SipAccount(os.environ['SIP_USERNAME'], os.environ['SIP_PASSWORD'], os.environ['SIP_SERVER'], connection_type='UDP')

@account.on_incoming_call
async def handle_incoming_call(call):
    await call.accept()

async def main():
    print(f'[{time.time():.3f}] main() started')
    await account.register()
    print(f'[{time.time():.3f}] Registration returned')
    await account.unregister()

if __name__ == "__main__":
    asyncio.run(main())
