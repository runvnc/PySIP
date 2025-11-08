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

# NO decorator - commenting it out
# @account.on_incoming_call
# async def handle_incoming_call(call: SipCall):
#     await call.accept()

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
    
    # Wait 15 seconds
    await asyncio.sleep(15)
    
    print("\nStopping...")
    await call.stop()
    await call_task
    await account.unregister()

if __name__ == "__main__":
    asyncio.run(main())
