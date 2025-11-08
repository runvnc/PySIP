import asyncio
from PySIP.sip_account import SipAccount
from dotenv import load_dotenv
import os

load_dotenv()

async def main():
    account = SipAccount(
        os.environ['SIP_USERNAME'],
        os.environ['SIP_PASSWORD'],
        os.environ['SIP_SERVER'],
        connection_type='UDP'
    )
    await account.register()
    await asyncio.sleep(2)
    await account.unregister()

if __name__ == "__main__":
    asyncio.run(main())
