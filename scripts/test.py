import asyncio
from PySIP.call_handler import CallHandler

DELAY_ERR_MESSAGE = (
    "We did not receive any input. Please provide the required information."
)


async def testbot(call_handler: CallHandler):
    try:
        print("Call hander TOP")
        await asyncio.sleep(20)

    except RuntimeError:
        print("The call was disconnected. Stopping the bot...")
