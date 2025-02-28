from classes.layers.base import OSILayer
from classes.layers.physical import PhysicalLayer
import struct
import zlib
from typing import Union, Dict
import socket

class DataLinkLayer(OSILayer):
    # Class-level ARP table (simulating network-wide ARP)
    _arp_table: Dict[str, str] = {}

    def __init__(self, physical_layer: PhysicalLayer, mac_address: str):
        self.physical_layer = physical_layer
        self.mac_address = mac_address.replace(':', '')  # Store without colons
        self.layer_name = "DataLink"
        self.network_layer = None  # Will be set by NetworkLayer during initialization

    def register_network_layer(self, network_layer):
        """Allow Network Layer to register itself for IP resolution"""
        self.network_layer = network_layer

    @classmethod
    def register_mac_ip_pair(cls, mac_address: str, ip_address: str):
        """Register MAC-IP pair in the ARP table"""
        cls._arp_table[ip_address] = mac_address.replace(':', '')

    def _resolve_mac_address(self, ip_address: str) -> bytes:
        """Resolve IP to MAC address (simulated ARP)"""
        if not self.network_layer:
            raise RuntimeError("Network layer not registered")

        # Check ARP table for MAC address
        if ip_address not in self._arp_table:
            self._log_operation("ARP", f"No MAC found for IP {ip_address}", 1)
            return b'\xFF' * 6  # Fallback to broadcast if not found

        mac_str = self._arp_table[ip_address]
        self._log_operation("ARP", f"Resolved IP {ip_address} to MAC {mac_str}", 1)
        return bytes.fromhex(mac_str)

    def _calculate_crc(self, data: bytes) -> int:
        return zlib.crc32(data) & 0xFFFFFFFF

    def send(self, data: bytes) -> bytes:
        if not self.network_layer:
            raise RuntimeError("Network layer not registered")

        # Create Ethernet II frame structure
        self._log_operation("SEND", "Creating Ethernet frame", 0, payload_size=len(data))
        
        dest_mac = self._resolve_mac_address(socket.inet_ntoa(self.network_layer.destination_ip))
        source_mac = bytes.fromhex(self.mac_address)
        ethertype = struct.pack('!H', 0x0800)  # IPv4
        crc = struct.pack('!L', self._calculate_crc(data))
        
        self._log_operation("SEND", "Frame details", 1,
                          dest_mac=dest_mac.hex(),
                          source_mac=source_mac.hex(),
                          ethertype=ethertype.hex(),
                          crc=crc.hex())
        
        frame = dest_mac + source_mac + ethertype + data + crc
        return self.physical_layer.send(frame)

    def receive(self, data: bytes) -> Union[bytes, None]:
        """Process received frame and check if it's intended for this device"""
        if len(data) < 14:  # Minimum Ethernet frame size without CRC
            self._log_operation("RECEIVE", "Invalid frame size", 1)
            return None

        dest_mac = data[0:6]
        source_mac = data[6:12]
        ethertype = data[12:14]
        payload = data[14:-4]
        received_crc = data[-4:]

        self._log_operation("RECEIVE", "Frame received", 1,
                          dest_mac=dest_mac.hex(),
                          source_mac=source_mac.hex(),
                          ethertype=ethertype.hex())

        # Check if frame is intended for this device or is broadcast
        if dest_mac != bytes.fromhex(self.mac_address) and dest_mac != b'\xFF' * 6:
            self._log_operation("RECEIVE", "Frame not for this device", 1)
            return None

        # Verify CRC
        calculated_crc = struct.pack('!L', self._calculate_crc(payload))
        if calculated_crc != received_crc:
            self._log_operation("RECEIVE", "CRC check failed", 1)
            return None

        return payload
