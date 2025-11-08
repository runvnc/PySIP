import asyncio
from PySIP.sip_account import SipAccount
from PySIP.sip_call import SipCall
from dotenv import load_dotenv
import os

load_dotenv()

# Patch to see what auth header we're generating
import PySIP.sip_call
original_build_auth_header = PySIP.sip_call.SipCall.build_auth_header

def debug_build_auth_header(self, uri, nonce, realm, response, opaque=None, qop=None, nc=None, cnonce=None, proxy_auth=False):
    result = original_build_auth_header(self, uri, nonce, realm, response, opaque, qop, nc, cnonce, proxy_auth)
    print(f'\n=== Building Auth Header ===')
    print(f'  proxy_auth: {proxy_auth}')
    print(f'  uri: {uri}')
    print(f'  realm: {realm}')
    print(f'  nonce: {nonce[:20]}...')
    print(f'  opaque: {opaque}')
    print(f'  qop: {qop}')
    print(f'  response: {response[:20]}...')
    print(f'  Header: {result[:100]}...')
    return result

PySIP.sip_call.SipCall.build_auth_header = debug_build_auth_header

# Also patch generate_auth_header to see the digest calculation
original_generate_auth = PySIP.sip_call.SipCall.generate_auth_header

def debug_generate_auth(self, method, uri, nonce, realm, qop=None, nc=None, cnonce=None):
    print(f'\n=== Generating Digest ===')
    print(f'  method: {method}')
    print(f'  uri: {uri}')
    print(f'  realm: {realm}')
    result = original_generate_auth(self, method, uri, nonce, realm, qop, nc, cnonce)
    print(f'  digest: {result[:20]}...')
    return result

PySIP.sip_call.SipCall.generate_auth_header = debug_generate_auth

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
    print("Registered!\n")
    
    print("Making call...")
    call = account.make_call("16822625850")
    call_task = asyncio.create_task(call.start())
    
    await asyncio.sleep(10)
    
    await call.stop()
    await call_task
    await account.unregister()

if __name__ == "__main__":
    asyncio.run(main())
