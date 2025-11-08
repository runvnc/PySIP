import asyncio
from PySIP.sip_account import SipAccount
from PySIP.sip_call import SipCall
from dotenv import load_dotenv
import os

load_dotenv()

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
    print("registering")
    await account.register()
    print("registered")
    
    print("making call")
    call = account.make_call("16822625850")
    call_task = asyncio.create_task(call.start())

    # Wait a bit
    await asyncio.sleep(10)
    
    await call.stop()
    await call_task
    await account.unregister()

if __name__ == "__main__":
    asyncio.run(main())
