import asyncio
from PySIP.sip_account import SipAccount
import os
from dotenv import load_dotenv
import logging

load_dotenv()

# Set up detailed logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Monkey patch to track message flow
import PySIP.sip_client
original_message_handler = PySIP.sip_client.SipClient.message_handler

async def debug_message_handler(self, msg):
    print(f'\n=== SipClient.message_handler called ===')
    print(f'  Method: {msg.method}')
    print(f'  Status: {msg.status}')
    print(f'  Call-ID: {msg.call_id}')
    print(f'  CSeq: {msg.cseq}')
    print(f'  Has nonce: {msg.nonce is not None}')
    print(f'  Has realm: {msg.realm is not None}')
    result = await original_message_handler(self, msg)
    print(f'  Handler completed')
    return result

PySIP.sip_client.SipClient.message_handler = debug_message_handler

account = SipAccount(os.environ['SIP_USERNAME'], os.environ['SIP_PASSWORD'], os.environ['SIP_SERVER'], connection_type='UDP')

@account.on_incoming_call
async def handle_incoming_call(call):
    await call.accept()

print('Starting registration...')
try:
    asyncio.run(account.register())
    print('Registration complete!')
except Exception as e:
    print(f'Registration failed: {e}')
