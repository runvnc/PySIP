import asyncio
import logging
from typing import Callable, Dict, List
import uuid
import random

from PySIP.sip_call import SipCall
from PySIP.utils.retry_handler import RetryHandler

from .sip_core import SipCore, SipMessage, Counter
from .filters import SIPCompatibleMethods, SIPStatus, ConnectionType
from .utils.logger import logger
from .exceptions import NoPasswordFound, OperationTimeout, SIPError


__all__ = ["SipClient"]


class SipClient:
    def __init__(
        self,
        username,
        server,
        connection_type: str,
        password: str,
        *,
        register_duration=600,
        caller_id="",
        sip_core=None,
    ):
        self.username = username
        try:
            self.server_host = server.split(":")[0]
            self.port = server.split(":")[1]
        except IndexError:
            self.server_host = server
            self.port = 5060
        # Keep server with port for backward compatibility
        self.server = self.server_host + ":" + str(self.port)

        if password:
            self.password = password
        else:
            raise NoPasswordFound(
                "No password was provided please provide password to use for Digest auth."
            )

        self.CTS = "TLS" if "TLS" in connection_type else connection_type
        self.connection_type = ConnectionType(connection_type)
        self.reader, self.writer = None, None
        self.all_tasks: List[asyncio.Task] = []
        self.sip_core = (
            sip_core
            if sip_core is not None
            else SipCore(self.username, self.server, connection_type, password)
        )
        self.call_id = self.sip_core.gen_call_id()
        self.sip_core.on_message_callbacks.append(self.message_handler)
        self.register_counter = Counter(random.randint(1, 2000))
        self.register_tags = {"local_tag": "", "remote_tag": "", "type": "", "cseq": 0}
        self.registered: asyncio.Future = asyncio.Future()
        self.unregistered = asyncio.Event()
        self.register_duration = register_duration
        self.caller_id = caller_id if caller_id else username
        self.my_public_ip = None
        self.my_private_ip = None
        self._callbacks: Dict[str, List[Callable]] = {}
        self.retry_handler = RetryHandler()
        # Transaction management for registration
        self._register_lock = asyncio.Lock()
        self._pending_auth_nonce = None
        self._last_401_time = 0

    async def run(self):
        register_task = None
        receive_task = None
        tasks = []
        try:
            self.my_public_ip = await asyncio.to_thread(self.sip_core.get_public_ip)
            self.my_private_ip = await asyncio.to_thread(self.sip_core.get_local_ip)

            if (
                not self.sip_core.is_running.is_set()
                and not self.sip_core._is_connecting.is_set()
            ):
                # only connect if it is not already connected
                await self.sip_core.connect()

            elif self.sip_core._is_connecting.is_set():
                await self.sip_core.is_running.wait()

            register_task = asyncio.create_task(
                self.periodic_register(self.register_duration), name="Periodic Register"
            )
            tasks.append(register_task)
            if not self.sip_core.receive_task:
                receive_task = asyncio.create_task(
                    self.sip_core.receive(), name="Receive Messages Task"
                )
                self.sip_core.receive_task = receive_task
                tasks.append(self.sip_core.receive_task)

            # Wait for receive task to actually start receiving before starting registration
            logger.log(logging.DEBUG, "Waiting for receive task to be ready...")
            await self.sip_core.is_receiving.wait()
            logger.log(logging.DEBUG, "Receive task is ready, starting registration")

            try:
                self.all_tasks.extend(tasks)
                await asyncio.gather(*tasks)
            except asyncio.CancelledError:
                if receive_task.done():
                    pass
                if asyncio.current_task() and asyncio.current_task().cancelling() > 0:
                    raise

        except Exception as e:
            logger.log(logging.ERROR, e, exc_info=True)
            return

        finally:

            if register_task and not register_task.done():
                register_task.cancel()
                try:
                    await register_task
                except asyncio.CancelledError:
                    pass  # Task cancellation is expected

            if receive_task and not receive_task.done():
                receive_task.cancel()
                try:
                    await receive_task
                except asyncio.CancelledError:
                    pass  # Task cancellation is expected

    async def stop(self):
        unregister = self.build_register_message(unregister=True)
        await self.sip_core.send(unregister)
        try:
            await asyncio.wait_for(self.unregistered.wait(), 4)
            logger.log(
                logging.INFO,
                "Sip Account: %s has been de-registered from the server",
                self.username,
            )
        except asyncio.TimeoutError:
            logger.log(
                logging.WARNING, "Failed to de-register Sip Account: %s", self.username
            )

        self.sip_core.is_running.clear()
        await self.sip_core.close_connections()
        self.registered = asyncio.Future()

    async def periodic_register(self, delay: float):
        while True:
            await self.register()

            sleep_task = asyncio.create_task(asyncio.sleep(delay - 5))
            event_cleared_task = asyncio.create_task(
                self.wait_for_event_clear(self.sip_core.is_running)
            )
            self.all_tasks.extend([sleep_task, event_cleared_task])

            _, pending = await asyncio.wait(
                [sleep_task, event_cleared_task], return_when="FIRST_COMPLETED"
            )

            for task in pending:
                task.cancel()

            if not self.sip_core.is_running.is_set():
                break

        logger.log(
            logging.DEBUG,
            "The app will no longer register. Registeration task stopped.",
        )

    async def wait_for_event_clear(self, event: asyncio.Event):
        while True:
            if not event.is_set():
                break

            await asyncio.sleep(0.1)

    async def check_connection_type(self):
        self.my_public_ip = await asyncio.to_thread(self.sip_core.get_public_ip)
        self.my_private_ip = await asyncio.to_thread(self.sip_core.get_local_ip)

        connection_types = [
            ConnectionType.UDP,
            ConnectionType.TCP,
            ConnectionType.TLS,
            ConnectionType.TLSv1,
        ]
        found_connections = [ConnectionType.UDP]
        found_connections.clear()

        for con in connection_types:
            self.sip_core.is_running.clear()
            self.sip_core.connection_type = con
            self.connection_type = con
            self.sip_core.port = (
                5061 if con in [ConnectionType.TLS, ConnectionType.TLSv1] else 5060
            )
            try:
                await self.sip_core.connect()
            except Exception:
                continue
            await self.register()

            reader = self.sip_core.udp_reader or self.sip_core.reader
            if not reader:
                return found_connections
            try:
                _ = await asyncio.wait_for(reader.read(), 1)
                found_connections.append(con)
            except asyncio.TimeoutError:
                continue
        return found_connections

    def build_register_message(
        self, auth=False, received_message=None, unregister=False
    ):
        """
        Build a SIP REGISTER message with or without authentication.
        """
        # Generate unique identifiers for the message
        branch_id = str(uuid.uuid4()).upper()
        # Initialize transaction
        call_id = self.call_id

        # Start building the SIP message based on authentication need
        if auth:
            # Handling authenticated REGISTER request
            unregister = True if self.register_tags["type"] == "UNREGISTER" else False
            if not received_message:
                return
            
            nonce = received_message.nonce
            realm = received_message.realm
            opaque = received_message.opaque
            
            # CRITICAL FIX: Increment CSeq for new transaction
            cseq = next(self.register_counter)
            self.register_tags["cseq"] = cseq
            
            # URI must include transport parameter
            uri = f"sip:{self.server_host};transport={self.CTS}"

            # Check for qop in WWW-Authenticate header
            qop = received_message.qop
            nc = None
            cnonce = None
            
            auth_header = received_message.get_header("WWW-Authenticate")
            if auth_header and qop:
                nc = "00000001"  # Initial nonce count
                cnonce = "".join(
                    random.choices("0123456789abcdef", k=16)
                )  # Random cnonce

            # Generate response with appropriate parameters
            response = self.sip_core.generate_response(
                method="REGISTER",
                nonce=nonce,
                realm=realm,
                uri=uri,
                qop=qop,
                nc=nc,
                cnonce=cnonce,
            )

            # Adjust Via and Contact headers for public IP and port if available
            # CRITICAL FIX: Use consistent IP addressing
            # Always prefer public IP once discovered to avoid load balancer confusion
            if self.my_public_ip:
                ip = self.my_public_ip
            elif received_message.public_ip:
                ip = received_message.public_ip
            else:
                ip = self.my_private_ip
            port = received_message.rport
            from_tag = self.register_tags["local_tag"]
            expires = ";expires=0" if unregister else ""
            expires_field = (
                f"Expires: {self.register_duration}\r\n" if not unregister else ""
            )

            # CRITICAL FIX: Generate new branch ID for new transaction
            new_branch = str(uuid.uuid4()).upper()
            
            # Build Authorization header based on qop presence
            auth_header = (
                f'Authorization: Digest username="{self.username}", '
                f'realm="{realm}", '
                f'nonce="{nonce}", '
                f'uri="{uri}", '
                f'response="{response}", '
                f'algorithm="MD5"'
            )

            if qop:
                auth_header += f', qop=auth, nc={nc}, cnonce="{cnonce}"'
            
            # Add opaque if present
            if opaque:
                auth_header += f', opaque="{opaque}"'
            auth_header += "\r\n"

            # Construct the complete REGISTER request with Authorization header
            msg = (
                f"REGISTER sip:{self.server};transport={self.CTS} SIP/2.0\r\n"
                f"Via: SIP/2.0/{self.CTS} {ip}:{port};rport;branch={new_branch};alias\r\n"
                f"Max-Forwards: 70\r\n"
                # REGISTER must use username, not caller_id (phone number)
                f"From: <sip:{self.username}@{self.server}>;tag={from_tag}\r\n"
                f"To: <sip:{self.username}@{self.server}>\r\n"
                f"Call-ID: {call_id}\r\n"
                f"CSeq: {cseq} REGISTER\r\n"
                f"Contact: <sip:{self.username}@{ip}:{port};transport={self.CTS}>{expires}\r\n"
                f"{expires_field}"
                f"{auth_header}"
                f"Content-Length: 0\r\n\r\n"
            )
        else:
            # Handling unauthenticated REGISTER request
            # CRITICAL FIX: Use public IP if available for consistency
            ip = self.my_public_ip if self.my_public_ip else self.my_private_ip
            
            port = self.port
            _, my_public_port = self.sip_core.get_extra_info("sockname")
            if not self.register_tags["local_tag"]:
                self.register_tags["local_tag"] = self.sip_core.generate_tag()

            cseq = next(self.register_counter)
            expires = ";expires=0" if unregister else ""
            expires_field = (
                f"Expires: {self.register_duration}\r\n" if not unregister else ""
            )
            self.register_tags["type"] = "UNREGISTER" if unregister else "REGISTER"

            # Construct the REGISTER request without Authorization header
            msg = (
                f"REGISTER sip:{self.server};transport={self.CTS} SIP/2.0\r\n"
                f"Via: SIP/2.0/{self.CTS} {ip}:{my_public_port};rport;branch={branch_id};alias\r\n"
                f"Max-Forwards: 70\r\n"
                # REGISTER must use username, not caller_id (phone number)
                f"From: <sip:{self.username}@{self.server}>;tag={self.register_tags['local_tag']}\r\n"
                f"To: <sip:{self.username}@{self.server}>\r\n"
                f"Call-ID: {call_id}\r\n"
                f"CSeq: {cseq} REGISTER\r\n"
                f"Contact: <sip:{self.username}@{self.my_public_ip}:{my_public_port};transport={self.CTS}>{expires}\r\n"
                f"{expires_field}"
                f"Content-Length: 0\r\n\r\n"
            )

        return msg

    def ok_generator(self, data_parsed: SipMessage):
        peer_ip, peer_port = self.sip_core.get_extra_info("peername")
        _, port = self.sip_core.get_extra_info("sockname")
        my_public_ip = self.my_public_ip

        msg = "SIP/2.0 200 OK\r\n"
        msg += f"Via: {data_parsed.get_header('Via')}\r\n"

        if data_parsed.method == "OPTIONS":
            to_tag = self.sip_core.generate_tag()
            msg += f"From: {data_parsed.get_header('From')}\r\n"
            msg += f"To: <sip:{self.username}@{my_public_ip}>;tag={to_tag}\r\n"
        else:
            msg += f"From: <sip:{self.username}@{self.server}>;tag={data_parsed.from_tag}\r\n"
            msg += (
                f"To: <sip:{self.username}@{self.server}>;tag={data_parsed.to_tag}\r\n"
            )

        msg += f"Call-ID: {data_parsed.call_id}\r\n"
        msg += f"CSeq: {data_parsed.cseq} {data_parsed.method}\r\n"
        msg += f"Contact: <sip:{self.username}@{my_public_ip}:{port};transport={self.CTS.upper()}>\r\n"
        msg += f"Allow: {', '.join(SIPCompatibleMethods)}\r\n"
        msg += "Supported: replaces, timer\r\n"
        msg += "Content-Length: 0\r\n\r\n"

        return msg

    async def ping(self):
        options_message = ""  # TODO Impmelement an options generator when required
        await self.sip_core.send(options_message)

    async def reregister(self, auth, data):
        msg = self.build_register_message(auth, data)

        await self.sip_core.send(msg)
        return

    async def register(self):
        """Register with retry logic"""
        msg = self.build_register_message()
        operation_id = f"REGISTER_{self.call_id}_{self.register_counter.current()}"

        try:
            success = await self.retry_handler.execute_with_retry(
                lambda: self.sip_core.send(msg), operation_id, timeout=4.0
            )
            if success:
                if self.registered and not self.registered.done():
                    self.registered.set_result(True)

                logger.log(
                    logging.INFO,
                    f"Sip Account: {self.username} registered to the server.",
                )

            return success

        except OperationTimeout:
            logger.error(f"Registration timed out for {self.username}")
            if self.registered and not self.registered.done():
                self.registered.set_result(False)
            return False

        except SIPError as e:
            logger.error(f"Registration failed for {self.username}: {str(e)}")
            if self.registered and not self.registered.done():
                self.registered.set_result(False)

            return False

    async def _send_register(self):
        """Internal method to send register message"""
        msg = self.build_register_message()
        await self.sip_core.send(msg)

    async def message_handler(self, msg: SipMessage):
        # This is the main message handler inside the class
        # its like other handlers outside the class that can
        # be accessed with @:meth:`Client.on_message` the only
        # difference is that its handled inside the :obj:`Client`
        # and it's onlt for developer's usage. unlike other handlers
        # it has no filters for now.
        to = msg.get_header("To")
        if (
            not msg.call_id == self.call_id and self.username not in to
        ):  # Filter only current call
            return  # These are just for extra check and not necessary

        logger.log(
            logging.DEBUG,
            f"message_handler: method={msg.method}, status={msg.status}, call_id={msg.call_id}, cseq={msg.cseq}"
        )
        logger.log(logging.DEBUG, f"Full SIP Message:\n{str(msg.data)}")

        if msg.status == SIPStatus(401) and msg.method == "REGISTER":
            # CRITICAL FIX: Use lock to prevent multiple simultaneous auth attempts
            # This prevents the race condition where multiple 401s from different servers
            # trigger multiple reregister attempts with the same CSeq/branch
            async with self._register_lock:
                import time
                current_time = time.time()
                
                # Debounce: ignore 401s that arrive within 100ms of each other
                if current_time - self._last_401_time < 0.1:
                    logger.log(
                        logging.DEBUG,
                        f"Ignoring duplicate 401 (nonce={msg.nonce[:20]}...) - too soon after previous"
                    )
                    return
                
                # Only process if this is a new nonce (different server or new challenge)
                if msg.nonce == self._pending_auth_nonce:
                    logger.log(
                        logging.DEBUG,
                        f"Ignoring duplicate 401 with same nonce={msg.nonce[:20]}..."
                    )
                    return
                
                # This is a new authentication challenge
                self._pending_auth_nonce = msg.nonce
                self._last_401_time = current_time
                
                logger.log(
                    logging.DEBUG,
                    f"Processing 401 with nonce={msg.nonce[:20]}... from server {msg.get_header('Server')}"
                )
                
                await self.reregister(True, msg)
                logger.log(logging.DEBUG, "Register message has been sent to the server")

        elif msg.status == SIPStatus(200) and msg.method == "REGISTER":
            # Clear pending auth state on success
            self._pending_auth_nonce = None
            
            # This is when we receive the response for the register
            # Complete ANY pending REGISTER operation for this call_id
            for op_id in list(self.retry_handler.pending_operations.keys()):
                if op_id.startswith(f"REGISTER_{msg.call_id}_"):
                    self.retry_handler.complete_operation(op_id)
                    logger.log(
                        logging.DEBUG,
                        f"Completed operation {op_id} after receiving 200 OK"
                    )

            # In case the response is of Un-register we set this
            if self.register_tags["type"] == "UNREGISTER":
                if msg.cseq == self.register_tags["cseq"]:
                    self.unregistered.set()

        elif msg.data.startswith(
            "OPTIONS"
        ):  # If we recieve PING then PONG incase of keep-alive required
            logger.log(
                logging.DEBUG, "Keep-alive message received from the server. sending OK"
            )
            options_ok = self.ok_generator(msg)
            await self.sip_core.send(options_ok)

        elif msg.data.startswith("INVITE") and self.username in to:
            incoming_call = SipCall(
                self.username, self.password, self.server, "", sip_core=self.sip_core
            )
            for cb in self._get_callbacks("incoming_call_cb"):
                incoming_call._register_callback("incoming_call_cb", cb)

            await incoming_call.handle_incoming_call(msg)

    def _register_callback(self, cb_type, cb):
        self._callbacks.setdefault(cb_type, []).append(cb)

    def _get_callbacks(self, cb_type):
        return self._callbacks.get(cb_type, [])

    def _remove_callback(self, cb_type, cb):
        callbacks = self._callbacks.get(cb_type, [])
        if cb in callbacks:
            callbacks.remove(cb)
