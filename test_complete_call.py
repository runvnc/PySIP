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
    print("Registering...")
    await account.register()
    print("Registered successfully!")
    
    print("\nMaking call to 16822625850...")
    call = account.make_call("16822625850")
    
    # Set up call state monitoring
    @call.on_call_state_changed
    async def on_state_change(state):
        print(f"Call state changed to: {state}")
    
    @call.on_call_hanged_up
    async def on_hangup(reason):
        print(f"Call ended: {reason}")
    
    call_task = asyncio.create_task(call.start())
    
    # Wait for call to complete (or timeout after 60 seconds)
    try:
        await asyncio.wait_for(call_task, timeout=60)
    except asyncio.TimeoutError:
        print("Call timed out after 60 seconds")
        await call.stop()
    
    print("\nUnregistering...")
    await account.unregister()
    print("Done!")

if __name__ == "__main__":
    asyncio.run(main())
