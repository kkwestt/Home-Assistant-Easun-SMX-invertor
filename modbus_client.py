import logging
import socket
import struct
import threading
import time
from typing import Any, Dict, Optional

_LOGGER = logging.getLogger(__name__)

class EasunModbusClient:
    """EASUN SMX custom Modbus client."""

    def __init__(self, host: str, port: int = 502):
        """Initialize the client."""
        self.host = host
        self.port = port
        self._connected = False
        self._tcp_server = None
        self._tcp_client_socket = None
        self._local_ip = None
        self._tcp_port = 8899
        self._lock = threading.Lock()
        self._last_activity = 0
        self._connection_timeout = 60  # 1 minute (reduced from 2 minutes for faster reconnection)
        self._transaction_id = 1
        self._consecutive_failures = 0

    def _get_local_ip(self) -> str:
        """Get local IP address that can reach the inverter."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.host, 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception as err:
            _LOGGER.error("Failed to determine local IP: %s", err)
            return "0.0.0.0"

    def _is_connection_stale(self) -> bool:
        """Check if connection is stale."""
        if not self._connected:
            return True
        time_since_activity = time.time() - self._last_activity
        if time_since_activity > self._connection_timeout:
            _LOGGER.info("Connection is stale (last activity: %.1f seconds ago, timeout: %d seconds), will reconnect", 
                        time_since_activity, self._connection_timeout)
            return True
        return False

    def _find_free_port(self) -> int:
        """Find a free TCP port starting from 8899."""
        for port in range(8899, 8999):
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                test_socket.bind((self._local_ip, port))
                test_socket.close()
                return port
            except OSError:
                continue
        return 8899  # Fallback

    def connect(self) -> bool:
        """Connect to the inverter using custom protocol."""
        try:
            # Disconnect if already connected
            if self._connected:
                self.disconnect()

            self._local_ip = self._get_local_ip()
            _LOGGER.info("Using local IP: %s", self._local_ip)
            
            if self._local_ip == "0.0.0.0":
                _LOGGER.error("Failed to determine local IP address")
                return False

            # Find free port
            self._tcp_port = self._find_free_port()
            _LOGGER.info("Using TCP port: %s", self._tcp_port)

            # Start TCP server
            self._tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Allow reuse of address in TIME_WAIT state
            try:
                self._tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass  # SO_REUSEPORT not available on all platforms
            
            try:
                self._tcp_server.bind((self._local_ip, self._tcp_port))
            except OSError as err:
                _LOGGER.error("Failed to bind TCP server to %s:%s - %s", self._local_ip, self._tcp_port, err)
                _LOGGER.error("Try restarting Home Assistant to free up the port")
                self.disconnect()
                return False
            
            self._tcp_server.listen(1)
            self._tcp_server.settimeout(30)

            _LOGGER.info("TCP server listening on %s:%s", self._local_ip, self._tcp_port)

            # Send UDP packet
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.settimeout(10)
            
            udp_message = f"set>server={self._local_ip}:{self._tcp_port};".encode()
            _LOGGER.info("Sending UDP message: %s to %s:58899", udp_message.decode(), self.host)
            
            try:
                udp_socket.sendto(udp_message, (self.host, 58899))
                _LOGGER.info("UDP packet sent successfully")
            except Exception as err:
                _LOGGER.error("Failed to send UDP packet: %s", err)
                udp_socket.close()
                self.disconnect()
                return False

            # Wait for UDP response
            try:
                data, addr = udp_socket.recvfrom(1024)
                response = data.decode().strip()
                _LOGGER.info("UDP response: %s", response)

                status = None
                if response.startswith("rsp>server="):
                    status = response.split("=", 1)[1].split(";", 1)[0]

                if status not in ("1", "2"):
                    _LOGGER.error("Unexpected UDP response: %s", response)
                    udp_socket.close()
                    self.disconnect()
                    return False

                if status == "2":
                    _LOGGER.warning(
                        "Datalogger has existing server configuration; sending disconnect command first"
                    )

                    # Send disconnect command
                    disconnect_message = b"set>server=0;"
                    _LOGGER.info("Sending UDP disconnect message: %s to %s:58899", disconnect_message.decode(), self.host)
                    try:
                        udp_socket.sendto(disconnect_message, (self.host, 58899))
                        _LOGGER.info("UDP disconnect packet sent successfully")

                        # Wait for disconnect response
                        data, addr = udp_socket.recvfrom(1024)
                        response = data.decode().strip()
                        _LOGGER.info("UDP disconnect response: %s", response)

                        # Wait a moment for datalogger to disconnect
                        time.sleep(2)

                        # Now send the connect command again
                        _LOGGER.info("Sending UDP connect message again: %s to %s:58899", udp_message.decode(), self.host)
                        udp_socket.sendto(udp_message, (self.host, 58899))
                        _LOGGER.info("UDP connect packet sent successfully")

                        # Wait for connect response
                        data, addr = udp_socket.recvfrom(1024)
                        response = data.decode().strip()
                        _LOGGER.info("UDP connect response: %s", response)

                        if response.startswith("rsp>server="):
                            status = response.split("=", 1)[1].split(";", 1)[0]
                            if status != "1":
                                _LOGGER.error("Failed to set new server configuration, status: %s", status)
                                udp_socket.close()
                                self.disconnect()
                                return False
                    except socket.timeout:
                        _LOGGER.error("No response from datalogger during reconnection")
                        udp_socket.close()
                        self.disconnect()
                        return False
                    except Exception as err:
                        _LOGGER.error("Failed during reconnection: %s", err)
                        udp_socket.close()
                        self.disconnect()
                        return False

            except socket.timeout:
                _LOGGER.error("No UDP response from datalogger")
                udp_socket.close()
                self.disconnect()
                return False
            finally:
                udp_socket.close()

            # Wait for TCP connection
            _LOGGER.info("Waiting for TCP connection from datalogger (timeout: 30s)...")
            try:
                self._tcp_client_socket, addr = self._tcp_server.accept()
                self._tcp_client_socket.settimeout(10)

                # Enable TCP keepalive to detect dead connections
                self._tcp_client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

                # Set keepalive parameters (may not work on all platforms)
                try:
                    # Linux
                    self._tcp_client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                    self._tcp_client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                    self._tcp_client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                except (AttributeError, OSError):
                    # macOS/Windows - use default keepalive settings
                    pass

                _LOGGER.info("Datalogger connected from %s", addr)
                self._connected = True
                self._last_activity = time.time()
                return True
            except socket.timeout:
                _LOGGER.error("Timeout: Datalogger did not connect via TCP within 30 seconds")
                _LOGGER.error("Check that:")
                _LOGGER.error("  1. The inverter/datalogger is powered on and connected to network")
                _LOGGER.error("  2. The IP address %s is correct", self.host)
                _LOGGER.error("  3. UDP port 58899 is not blocked by firewall")
                _LOGGER.error("  4. TCP port %s is not blocked by firewall", self._tcp_port)
                self.disconnect()
                return False

        except Exception as err:
            _LOGGER.error("Failed to connect: %s", err, exc_info=True)
            self.disconnect()
            return False

    def disconnect(self):
        """Disconnect from the inverter."""
        _LOGGER.info("Disconnecting from inverter...")
        self._connected = False
        self._consecutive_failures = 0

        if self._tcp_client_socket:
            try:
                self._tcp_client_socket.shutdown(socket.SHUT_RDWR)
            except:
                pass
            try:
                self._tcp_client_socket.close()
            except:
                pass
            self._tcp_client_socket = None
            _LOGGER.debug("Client socket closed")

        if self._tcp_server:
            try:
                self._tcp_server.shutdown(socket.SHUT_RDWR)
            except:
                pass
            try:
                self._tcp_server.close()
            except:
                pass
            self._tcp_server = None
            _LOGGER.debug("Server socket closed")

        # Give OS time to release the port
        time.sleep(0.5)

    def _calculate_crc16_modbus(self, data: bytes) -> int:
        """Calculate CRC16 Modbus."""
        table = [
            0x0000, 0xCC01, 0xD801, 0x1400, 0xF001, 0x3C00, 0x2800, 0xE401,
            0xA001, 0x6C00, 0x7800, 0xB401, 0x5000, 0x9C01, 0x8801, 0x4400
        ]
        crc = 0xFFFF
        for byte in data:
            crc = table[(byte ^ crc) & 15] ^ (crc >> 4)
            crc = table[((byte >> 4) ^ crc) & 15] ^ (crc >> 4)
        return crc

    def _format_hex(self, data: bytes) -> str:
        """Format bytes as hex string for logging."""
        return ' '.join(f'{b:02x}' for b in data)

    def _check_socket_valid(self) -> bool:
        """Check if socket is still valid."""
        if self._tcp_client_socket is None:
            return False
        
        try:
            # Check socket state - if it's closed, getsockopt will raise an error
            # On some platforms, we can check SO_ERROR
            try:
                error = self._tcp_client_socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if error != 0:
                    _LOGGER.debug("Socket has error state: %d", error)
                    return False
            except (OSError, AttributeError):
                # SO_ERROR may not be available on all platforms
                pass
            
            # Additional check: verify socket is not closed
            # If socket is closed, fileno() will raise an exception
            self._tcp_client_socket.fileno()
            return True
        except (OSError, AttributeError, ValueError):
            # Socket is closed or invalid
            return False

    def _receive_full_response(self) -> Optional[bytes]:
        """Receive full Modbus TCP response by reading header first, then payload."""
        try:
            # Read Modbus TCP header (6 bytes: transaction_id + protocol_id + length)
            header = b""
            while len(header) < 6:
                chunk = self._tcp_client_socket.recv(6 - len(header))
                if not chunk:
                    _LOGGER.error("Connection closed while reading header")
                    return None
                header += chunk
            
            # Parse length field (bytes 4-5, big-endian)
            length = struct.unpack('>H', header[4:6])[0]
            
            # Sanity check: Modbus TCP length should be reasonable (max 260 bytes for Modbus)
            # But this device uses custom protocol, so allow up to 1024 bytes
            if length > 1024:
                _LOGGER.error("Invalid response length: %d bytes (max 1024)", length)
                return None
            
            if length == 0:
                _LOGGER.error("Zero length response")
                return None
            
            # Read the rest of the packet (unit_id + function_code + data)
            payload = b""
            while len(payload) < length:
                chunk = self._tcp_client_socket.recv(length - len(payload))
                if not chunk:
                    _LOGGER.error("Connection closed while reading payload (got %d/%d bytes)", 
                                 len(payload), length)
                    return None
                payload += chunk
            
            # Combine header and payload
            response = header + payload
            return response
            
        except socket.timeout:
            _LOGGER.error("Timeout while receiving response")
            return None
        except (ConnectionResetError, BrokenPipeError, OSError) as err:
            _LOGGER.error("Connection error while receiving: %s", err)
            return None
        except struct.error as err:
            _LOGGER.error("Error parsing response header: %s", err)
            return None

    def _send_modbus_request(self, request: bytes) -> Optional[bytes]:
        """Send Modbus request and receive response."""
        if not self._connected or self._is_connection_stale():
            if not self.connect():
                return None

        # Verify socket is still valid before sending
        if self._tcp_client_socket is None or not self._check_socket_valid():
            _LOGGER.warning("TCP socket is invalid, reconnecting...")
            self._connected = False
            if not self.connect():
                return None

        try:
            _LOGGER.info(">>> Sending request (%d bytes): %s", len(request), self._format_hex(request))
            self._tcp_client_socket.sendall(request)
            self._last_activity = time.time()

            # Receive full response
            response = self._receive_full_response()
            if response:
                self._last_activity = time.time()
                _LOGGER.info("<<< Received response (%d bytes): %s", len(response), self._format_hex(response))
                return response
            else:
                # Empty or incomplete response means connection was closed or broken
                _LOGGER.error("<<< Failed to receive complete response")
                self.disconnect()
                return None

        except socket.timeout:
            _LOGGER.error("Timeout waiting for response")
            self.disconnect()
            return None
        except (ConnectionResetError, BrokenPipeError, OSError) as err:
            _LOGGER.error("Connection error: %s - reconnecting on next request", err)
            self.disconnect()
            return None
        except Exception as err:
            _LOGGER.error("Error sending request: %s", err, exc_info=True)
            self.disconnect()
            return None

    def read_register(self, address: int, register_type: str = "input", scale: float = 1.0) -> Optional[float]:
        """Read a single register.
        
        Packet format (EASUN custom):
        - Modbus TCP header: trid(2) + prot_id(2) + length(2) + unit_id(1) + func_code(1)
        - Modbus RTU payload: unit_id(1) + func_code(1) + register(2) + count(2) + crc(2)
        """
        try:
            # Transaction ID
            trid = struct.pack('>H', self._transaction_id)
            self._transaction_id += 1
            
            # Protocol ID (always 0x0001 for this device)
            prot_id = bytes([0x00, 0x01])
            
            # Modbus TCP wrapper
            tcp_unit_id = bytes([0xff])
            tcp_func_code = bytes([0x04])  # Gateway function code
            
            # Modbus RTU inner packet (this goes to the inverter via serial)
            rtu_unit_id = bytes([0xff])
            rtu_func_code = bytes([0x03])  # Read holding registers
            rtu_register = struct.pack('>H', address)
            rtu_count = bytes([0x00, 0x01])  # Read 1 register
            
            # Build RTU packet for CRC calculation
            rtu_packet = rtu_unit_id + rtu_func_code + rtu_register + rtu_count
            
            # Calculate CRC
            crc = self._calculate_crc16_modbus(rtu_packet)
            crc_bytes = struct.pack('<H', crc)  # Little-endian for CRC
            
            # Complete RTU packet with CRC
            rtu_packet_with_crc = rtu_packet + crc_bytes
            
            # TCP wrapper payload
            tcp_payload = tcp_unit_id + tcp_func_code + rtu_packet_with_crc
            
            # Length field (length of payload after this field)
            length = struct.pack('>H', len(tcp_payload))
            
            # Complete request
            request = trid + prot_id + length + tcp_payload
            
            _LOGGER.info("Reading register 0x%04X (type: %s, scale: %s)", address, register_type, scale)
            _LOGGER.debug("  Transaction ID: 0x%04X", self._transaction_id - 1)
            _LOGGER.debug("  RTU packet (before CRC): %s", self._format_hex(rtu_packet))
            _LOGGER.debug("  CRC: 0x%04X (%s)", crc, self._format_hex(crc_bytes))
            
            response = self._send_modbus_request(request)
            
            if not response:
                _LOGGER.error("No response received for register 0x%04X", address)
                return None
                
            if len(response) < 11:
                _LOGGER.error("Response too short for register 0x%04X: %d bytes (expected at least 11)", 
                             address, len(response))
                return None
            
            # Parse response
            # Response format: trid(2) + prot_id(2) + length(2) + tcp_unit(1) + tcp_func(1) + 
            #                  rtu_unit(1) + rtu_func(1) + byte_count(1) + data(N) + crc(2)
            
            resp_trid = struct.unpack('>H', response[0:2])[0]
            resp_prot = struct.unpack('>H', response[2:4])[0]
            resp_len = struct.unpack('>H', response[4:6])[0]
            tcp_unit = response[6]
            tcp_func = response[7]
            rtu_unit = response[8]
            rtu_func = response[9]
            byte_count = response[10]
            
            _LOGGER.debug("Response breakdown:")
            _LOGGER.debug("  Transaction ID: 0x%04X", resp_trid)
            _LOGGER.debug("  Protocol ID: 0x%04X", resp_prot)
            _LOGGER.debug("  Length: %d", resp_len)
            _LOGGER.debug("  TCP Unit: 0x%02X, TCP Func: 0x%02X", tcp_unit, tcp_func)
            _LOGGER.debug("  RTU Unit: 0x%02X, RTU Func: 0x%02X", rtu_unit, rtu_func)
            _LOGGER.debug("  Byte count: %d", byte_count)
            
            data_start = 11
            data_end = data_start + byte_count
            
            if len(response) < data_end + 2:  # +2 for CRC
                _LOGGER.error(
                    "Incomplete response for register 0x%04X (expected %d bytes, got %d)",
                    address,
                    data_end + 2,
                    len(response),
                )
                return None
            
            # Verify CRC
            rtu_response = response[8:data_end]  # From rtu_unit to end of data
            received_crc_bytes = response[data_end:data_end+2]
            received_crc = struct.unpack('<H', received_crc_bytes)[0]
            calculated_crc = self._calculate_crc16_modbus(rtu_response)
            
            _LOGGER.debug("  CRC check: received=0x%04X, calculated=0x%04X", received_crc, calculated_crc)
            
            if received_crc != calculated_crc:
                _LOGGER.warning(
                    "CRC mismatch for register 0x%04X (received: 0x%04X, calculated: 0x%04X) - continuing anyway",
                    address,
                    received_crc,
                    calculated_crc,
                )
                # Don't return None, continue with data extraction
            
            # Extract value
            value_bytes = response[data_start:data_start+2]
            value = struct.unpack('>H', value_bytes)[0]
            
            _LOGGER.debug("  Raw value: 0x%04X (%d)", value, value)
            
            # Handle signed values
            if value > 32767:
                value = value - 65536
            
            scaled_value = value * scale
            _LOGGER.info("Register 0x%04X = %s (raw: %d, scale: %s)", address, scaled_value, value, scale)
            
            return scaled_value

        except Exception as err:
            _LOGGER.error("Error reading register 0x%04X: %s", address, err, exc_info=True)
            return None

    def write_register(self, address: int, value: int) -> bool:
        """Write a single holding register."""
        try:
            # Transaction ID
            trid = struct.pack('>H', self._transaction_id)
            self._transaction_id += 1
            
            # Protocol ID
            prot_id = bytes([0x00, 0x01])
            
            # Modbus TCP wrapper
            tcp_unit_id = bytes([0xff])
            tcp_func_code = bytes([0x04])
            
            # Modbus RTU inner packet
            rtu_unit_id = bytes([0xff])
            rtu_func_code = bytes([0x10])  # Write multiple registers
            rtu_register = struct.pack('>H', address)
            rtu_count = bytes([0x00, 0x01])  # Write 1 register
            rtu_byte_count = bytes([0x02])  # 2 bytes of data
            rtu_data = struct.pack('>H', value)
            
            # Build RTU packet for CRC
            rtu_packet = rtu_unit_id + rtu_func_code + rtu_register + rtu_count + rtu_byte_count + rtu_data
            
            # Calculate CRC
            crc = self._calculate_crc16_modbus(rtu_packet)
            crc_bytes = struct.pack('<H', crc)
            
            # Complete RTU packet
            rtu_packet_with_crc = rtu_packet + crc_bytes
            
            # TCP wrapper
            tcp_payload = tcp_unit_id + tcp_func_code + rtu_packet_with_crc
            length = struct.pack('>H', len(tcp_payload))
            
            # Complete request
            request = trid + prot_id + length + tcp_payload
            
            _LOGGER.info("Writing value %d to register 0x%04X", value, address)
            response = self._send_modbus_request(request)
            
            if not response:
                return False
            
            _LOGGER.info("Successfully wrote value %s to register 0x%04X", value, address)
            return True

        except Exception as err:
            _LOGGER.error("Error writing register 0x%04X: %s", address, err, exc_info=True)
            return False

    def read_all_registers(self, registers: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Read all configured registers."""
        with self._lock:
            data = {}
            
            # Connect once for all reads
            if not self._connected or self._is_connection_stale():
                if not self.connect():
                    _LOGGER.warning("Failed to connect, returning empty data")
                    return data
            
            # Verify connection is still valid before starting reads
            if not self._check_socket_valid():
                _LOGGER.warning("Socket invalid before reading registers, reconnecting...")
                self._connected = False
                if not self.connect():
                    _LOGGER.warning("Failed to reconnect, returning empty data")
                    return data
            
            consecutive_errors = 0
            max_consecutive_errors = 3
            
            for key, config in registers.items():
                try:
                    value = self.read_register(
                        address=config["address"],
                        register_type=config["type"],
                        scale=config.get("scale", 1.0)
                    )
                    if value is not None:
                        data[key] = value
                        consecutive_errors = 0  # Reset error counter on success
                    else:
                        consecutive_errors += 1
                        _LOGGER.warning("Failed to read register %s (0x%04X), consecutive errors: %d", 
                                       key, config["address"], consecutive_errors)
                        
                        # If too many consecutive errors, try to reconnect
                        if consecutive_errors >= max_consecutive_errors:
                            _LOGGER.warning("Too many consecutive errors (%d), attempting reconnect...", 
                                          consecutive_errors)
                            self._connected = False
                            if self.connect():
                                consecutive_errors = 0
                            else:
                                _LOGGER.error("Reconnection failed, stopping read cycle")
                                break
                    
                    # Small delay between reads
                    time.sleep(0.1)
                    
                except Exception as err:
                    consecutive_errors += 1
                    _LOGGER.error("Exception reading register %s: %s", key, err, exc_info=True)
                    
                    if consecutive_errors >= max_consecutive_errors:
                        _LOGGER.warning("Too many consecutive errors, attempting reconnect...")
                        self._connected = False
                        if self.connect():
                            consecutive_errors = 0
                        else:
                            _LOGGER.error("Reconnection failed, stopping read cycle")
                            break
            
            if not data:
                _LOGGER.warning("No data read from any registers")
            else:
                _LOGGER.debug("Successfully read %d out of %d registers", len(data), len(registers))
            
            return data
