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
    print('Registering in async main...')
    await account.register()
    print('Registration complete!')

if __name__ == "__main__":
    asyncio.run(main())
