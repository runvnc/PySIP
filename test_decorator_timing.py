import asyncio
from PySIP.sip_account import SipAccount
import os
from dotenv import load_dotenv

load_dotenv()

print('Creating account...')
account = SipAccount(os.environ['SIP_USERNAME'], os.environ['SIP_PASSWORD'], os.environ['SIP_SERVER'], connection_type='UDP')
print('Account created')

print('\nDefining decorator...')
@account.on_incoming_call
async def handle_incoming_call(call):
    await call.accept()
print('Decorator defined')

print('\nStarting registration...')
asyncio.run(account.register())
print('Registration complete!')
