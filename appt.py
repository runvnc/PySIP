import asyncio
from PySIP.sip_account import SipAccount
from PySIP.sip_call import SipCall
#from scripts.appointment_booking_bot import appointment_booking_bot
from scripts.test import testbot
from dotenv import load_dotenv
import os
import logging
# Load environment variables
load_dotenv()
logging.basicConfig(level=logging.DEBUG)


# Initialize SIP account with credentials from .env file
account = SipAccount(
    os.environ["SIP_USERNAME"],
    os.environ["SIP_PASSWORD"],
    os.environ["SIP_SERVER"],
    caller_id="+17733377083",  # Your verified Telnyx phone number
    connection_type="UDP",  # Specify UDP to skip auto-detection
)

@account.on_incoming_call
async def handle_incoming_call(call: SipCall):
    await call.accept()
    await call.call_handler.say("We have received your call successfully")

async def main():
    # Register the SIP account
    print("registering")
    await account.register()
    print("registered")
    # Make a call to a test number (e.g., '111')
    print("calling")
    call = account.make_call("+16822625850")
    call_task = asyncio.create_task(call.start())
   
    # Run the appointment booking bot
    #await testbot(call.call_handler)
    #await appointment_booking_bot(call.call_handler, customer_name="John")

    # Wait for the call to complete, then unregister
    await call_task
    print("call ended")
    await account.unregister()

if __name__ == "__main__":
    asyncio.run(main())

