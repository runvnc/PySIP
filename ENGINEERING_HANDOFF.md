# PySIP Telnyx Integration - Engineering Handoff

**Date:** 2025-11-07  
**Session Duration:** ~3 hours  
**Status:** REGISTER authentication ✅ COMPLETE | INVITE authentication ⚠️ IN PROGRESS

---

## Executive Summary

Successfully fixed PySIP library to work with Telnyx SIP registration. The library can now register accounts with Telnyx, but outbound calls require additional authentication (407 Proxy Authentication) that needs to be implemented.

---

## What Works ✅

1. **SIP REGISTER authentication** - Fully functional
2. **Account registration with Telnyx** - Complete  
3. **Incoming call handler decorator** - Fixed and working
4. **IPv4/IPv6 handling** - Resolved
5. **All SIP protocol fixes** - Applied and tested

**Test Results:**
- `test_simple_register.py` - ✅ SUCCESS
- `final_test.py` - ✅ SUCCESS  
- `appt.py` registration - ✅ SUCCESS

---

## What Needs Work ⚠️

1. **INVITE authentication (407 Proxy Authentication Required)** - Not implemented
   - Telnyx requires digest authentication for outbound calls
   - Similar to REGISTER authentication but for INVITE messages
   - Error: "Call hanged up due to: Proxy Authentication Required"
   - Location: `/files/PySIP/PySIP/sip_call.py` (1013 lines)

---

## Files Modified

### 1. `/files/PySIP/PySIP/sip_core.py`

**Changes:**
- Added `_opaque` property to `SipMessage` class
- Added opaque parsing from WWW-Authenticate header (line ~750)
- Fixed qop parsing to handle missing qop parameter (line ~746)
- Changed public IP detection from `api64.ipify.org` to `api.ipify.org` for IPv4 only (line ~84)
- Added debug logging for UDP receive and message processing (lines ~313, ~332)

**Key Code Sections:**
```python
# Line ~532: Added opaque property
self._opaque = None

# Line ~654: Added opaque getter/setter
@property
def opaque(self):
    return self._opaque

# Line ~750: Parse opaque from WWW-Authenticate
try:
    self.opaque = auth_header.split('opaque="')[1].split('"')[0]
except IndexError:
    self.opaque = None

# Line ~84: IPv4-only public IP
external_ip = requests.get(
    "https://api.ipify.org?format=json", timeout=8
).json()["ip"]
```

### 2. `/files/PySIP/PySIP/sip_client.py`

**Changes:**
- Added `server_host` to separate hostname from port (line ~33)
- Fixed URI in Authorization header to exclude port (line ~238)
- Added opaque parameter to Authorization header (line ~280)
- Fixed retry handler to complete ANY pending REGISTER operation for a call_id (line ~432)

**Key Code Sections:**
```python
# Line ~33: Separate server host from port
self.server_host = server.split(":")[0]
self.port = server.split(":")[1]
self.server = self.server_host + ":" + str(self.port)

# Line ~238: URI without port
uri = f"sip:{self.server_host};transport={self.CTS}"

# Line ~280: Add opaque to Authorization
if opaque:
    auth_header += f', opaque="{opaque}"'

# Line ~432: Complete any pending REGISTER for this call_id
for op_id in list(self.retry_handler.pending_operations.keys()):
    if op_id.startswith(f"REGISTER_{msg.call_id}_"):
        self.retry_handler.complete_operation(op_id)
```

### 3. `/files/PySIP/PySIP/sip_account.py`

**Changes:**
- Fixed `on_incoming_call` decorator to return the function (line ~150)

**Key Code:**
```python
# Line ~150: Return function instead of None
return func  # Return the original function, not None
```

### 4. `/files/PySIP/appt.py`

**Changes:**
- Added `from PySIP.sip_call import SipCall` import
- Set `connection_type="UDP"` to skip auto-detection
- Changed call number to `16822625850`
- Commented out appointment_booking_bot for testing

---

## Root Causes Identified

### Issue 1: Missing opaque parameter
**Problem:** Telnyx includes an `opaque` parameter in WWW-Authenticate that must be echoed back  
**Solution:** Added opaque parsing and inclusion in Authorization header  
**Impact:** Critical - registration failed without this

### Issue 2: Wrong URI format
**Problem:** URI included port (`:5060`) which should not be in digest calculation  
**Solution:** Created `server_host` to separate hostname from port  
**Impact:** Critical - authentication failed with port in URI

### Issue 3: qop parsing crash
**Problem:** Code assumed qop parameter always present, crashed when missing  
**Solution:** Added try/except around qop parsing  
**Impact:** High - caused crashes on Telnyx which doesn't send qop

### Issue 4: IPv6 instead of IPv4
**Problem:** `api64.ipify.org` returns IPv6, but connecting via IPv4  
**Solution:** Changed to `api.ipify.org` for IPv4 only  
**Impact:** Critical - Via/Contact headers had wrong IP address type

### Issue 5: Retry handler CSeq mismatch
**Problem:** CSeq increments during re-registration, but retry handler waits for original CSeq  
**Solution:** Complete ANY pending REGISTER operation for the call_id  
**Impact:** High - caused timeout errors even when registration succeeded

### Issue 6: Decorator return value
**Problem:** `on_incoming_call` decorator returned None instead of function  
**Solution:** Return the original function  
**Impact:** Medium - broke decorator pattern

---

## Testing

### Test Files Created

1. **`test_with_opaque.py`** - Tests opaque parameter and transport in URI
2. **`test_simple_register.py`** - Bypasses retry handler for clean test
3. **`final_test.py`** - Comprehensive test of all fixes
4. **`debug_registration.py`** - Detailed message logging
5. **`test_username_formats.py`** - Tests different username formats
6. **`test_domain_split.py`** - Tests server/domain separation

### How to Test

```bash
cd /files/PySIP

# Test basic registration (bypasses PySIP retry handler)
python test_simple_register.py

# Test full PySIP registration
python final_test.py

# Test with actual app
python appt.py
```

### Expected Results

**Working:**
- Registration completes successfully
- "Sip Account: userjason43702 registered to the server."
- No timeout errors

**Current Issue:**
- Registration works ✅
- Call attempt fails with "Proxy Authentication Required" ❌

---

## Next Steps

### Immediate (Required for outbound calls)

1. **Implement 407 Proxy Authentication for INVITE**
   - Location: `/files/PySIP/PySIP/sip_call.py`
   - Similar to REGISTER authentication in `sip_client.py`
   - Need to:
     - Detect 407 response to INVITE
     - Extract nonce, realm, opaque from Proxy-Authenticate header
     - Generate digest response
     - Re-send INVITE with Proxy-Authorization header

2. **Test outbound calls**
   - Verify INVITE authentication works
   - Test call to real number
   - Verify audio/RTP streams

### Future Enhancements

1. **Improve retry handler**
   - Better operation tracking
   - Handle CSeq increments properly
   - Reduce false timeout warnings

2. **Add more robust error handling**
   - Better error messages
   - Graceful degradation

3. **Documentation**
   - Document all Telnyx-specific requirements
   - Add examples for common use cases

---

## Code Patterns to Follow

### For INVITE Authentication (407)

Follow the same pattern as REGISTER authentication:

```python
# In sip_call.py message handler
if msg.status == SIPStatus(407) and msg.method == "INVITE":
    # Extract auth parameters
    nonce = msg.nonce
    realm = msg.realm
    opaque = msg.opaque
    
    # Generate response
    uri = f"sip:{destination}@{server_host};transport={transport}"
    response = self.sip_core.generate_response(
        method="INVITE",
        nonce=nonce,
        realm=realm,
        uri=uri
    )
    
    # Build Proxy-Authorization header
    auth_header = (
        f'Proxy-Authorization: Digest username="{username}", '
        f'realm="{realm}", '
        f'nonce="{nonce}", '
        f'uri="{uri}", '
        f'response="{response}", '
        f'algorithm=MD5'
    )
    
    if opaque:
        auth_header += f', opaque="{opaque}"'
    
    # Re-send INVITE with authentication
    # ... (similar to reregister() in sip_client.py)
```

---

## Environment

**Credentials:**
- Server: `sip.telnyx.com:5060`
- Username: `userjason43702`
- Password: `^6puqZ?oT8S!`
- Transport: UDP

**Working Test Number:**
- Baresip successfully registers and works with same credentials
- Test call number: `16822625850`

---

## Key Learnings

1. **Telnyx requires opaque parameter** - Not optional like some providers
2. **URI format is critical** - Port must NOT be in digest URI
3. **IPv4 vs IPv6 matters** - Must match connection type
4. **407 is different from 401** - Proxy-Authorization vs Authorization header
5. **Baresip comparison was crucial** - Packet capture showed exact working format

---

## References

**Telnyx Documentation:**
- https://sip.telnyx.com/
- https://support.telnyx.com/en/articles/8096455-how-to-configure-a-sip-trunk

**PySIP GitHub:**
- https://github.com/moha-abdi/PySIP
- Issue #48: Domain/server separation (similar to our fix)

**Packet Captures:**
- `/tmp/sip_capture.pcap` - Baresip working registration
- `/tmp/pysip.pcap` - PySIP registration attempts

---

## Contact

For questions about these changes, refer to:
- This handoff document
- Test files in `/files/PySIP/test_*.py`
- Packet captures in `/tmp/*.pcap`

---

**End of Handoff Document**


---

## Update 2025-11-07 Evening Session

### 407 Proxy Authentication Implementation ✅

**Completed:**
- Added `proxy_auth` property to `SipMessage` class in `sip_core.py`
- Added Proxy-Authenticate header parsing (similar to WWW-Authenticate)
- Implemented 407 response handler in `sip_call.py` message_handler
- Created `build_auth_header()` method to support both Authorization and Proxy-Authorization headers
- Added 407 to error_handler exclusion list (alongside 401 and 487)
- Refactored authentication to separate digest generation from header building

**Code Changes:**

1. **sip_core.py** (lines 536, 665-673, 766-784):
   - Added `_proxy_auth` property initialization
   - Added `proxy_auth` getter/setter
   - Parse Proxy-Authenticate header for 407 responses
   - Extract nonce, realm, qop, opaque from Proxy-Authenticate

2. **sip_call.py** (lines 398-417, 667-685, 798):
   - Split `generate_auth_header()` into two methods:
     - `generate_auth_header()` - generates digest response only
     - `build_auth_header()` - builds complete header with proxy_auth flag
   - Added 407 handler before 401 handler in message_handler
   - Added 407 to error_handler exclusion list
   - Fixed URI in digest to use server_host without port

**Testing Results:**
- ✅ `test_simple_register.py` - REGISTER authentication works perfectly
- ⚠️ `appt.py` - Registration fails with callback loop (repeated 401s)
- ❓ INVITE 407 authentication - Not yet tested due to registration issue

### Known Issue: Callback Registration Loop 🐛

**Problem:**
When using `SipAccount` with the `@on_incoming_call` decorator, registration gets stuck in a loop receiving repeated 401 responses. The authenticated REGISTER is sent but never receives a 200 OK.

**Root Cause:**
Both `SipClient` and `SipCall` register their `message_handler` callbacks on the same shared `sip_core` instance:

```python
# In SipClient.__init__:
self.sip_core.on_message_callbacks.append(self.message_handler)

# In SipCall.__init__:
self.sip_core.on_message_callbacks.append(self.message_handler)
self.sip_core.on_message_callbacks.append(self.error_handler)
```

This causes every SIP message to be processed 3 times:
1. By SipClient.message_handler
2. By SipCall.message_handler  
3. By SipCall.error_handler

**Evidence:**
Debug output shows the same message being processed repeatedly:
```
DEBUG:PySIP.utils.logger:message_handler: method=REGISTER, status=None, call_id=..., cseq=613
DEBUG:PySIP.utils.logger:message_handler: method=REGISTER, status=401 Unauthorized, call_id=..., cseq=613
DEBUG:PySIP.utils.logger:message_handler: method=REGISTER, status=None, call_id=..., cseq=613
DEBUG:PySIP.utils.logger:message_handler: method=REGISTER, status=401 Unauthorized, call_id=..., cseq=613
[repeats indefinitely]
```

**Workaround:**
Commenting out the `@on_incoming_call` decorator allows registration to work, suggesting the issue is triggered when callbacks are registered.

**Next Steps to Fix:**
1. Investigate why multiple handlers cause 401 loop (they should be independent)
2. Consider:
   - Making handlers check if message is relevant before processing
   - Using a single shared message handler with routing
   - Ensuring handlers don't interfere with each other's operations
3. Add debug logging to see which handler is sending duplicate REGISTERs
4. Check if the issue is in the retry handler logic

### Files Modified This Session

- `PySIP/sip_core.py` - Added Proxy-Authenticate parsing
- `PySIP/sip_call.py` - Added 407 handler and refactored auth headers
- `.gitignore` - Added .venv/

### Commits

1. `5615378` - Fix Telnyx SIP registration authentication (previous session)
2. `df84256` - Add 407 Proxy Authentication support for INVITE (this session)

### Testing Commands

```bash
# Test basic registration (bypasses retry handler) - WORKS
cd /files/PySIP && python test_simple_register.py

# Test with SipAccount (has callback loop issue) - FAILS
cd /files/PySIP && python appt.py

# Test registration directly - WORKS
cd /files/PySIP && python -c "import asyncio; from PySIP.sip_account import SipAccount; import os; from dotenv import load_dotenv; load_dotenv(); account = SipAccount(os.environ['SIP_USERNAME'], os.environ['SIP_PASSWORD'], os.environ['SIP_SERVER'], connection_type='UDP'); asyncio.run(account.register())"
```

### Summary

**What Works:**
- ✅ REGISTER authentication (401) - Complete
- ✅ 407 Proxy Authentication code - Implemented
- ✅ Proxy-Authenticate header parsing - Complete
- ✅ Authorization vs Proxy-Authorization header generation - Complete

**What Needs Work:**
- ⚠️ Callback registration causing message processing loop
- ❓ INVITE 407 authentication - Needs testing once registration is stable
- ❓ End-to-end call flow with Telnyx - Blocked by registration issue

**Priority:**
Fix the callback loop issue before testing INVITE authentication. The 407 code is ready but can't be tested until we can successfully register and make calls.

---

**Session End: 2025-11-07 ~9 PM**
