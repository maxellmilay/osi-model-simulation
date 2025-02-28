from classes.layers.base import OSILayer
import random

class PhysicalLayer(OSILayer):
    def __init__(self, error_rate: float = 0.01):
        self.layer_name = "Physical"
        self.error_rate = error_rate

    def _simulate_noise(self, data: bytes) -> bytes:
        # Simulate signal interference
        if random.random() < self.error_rate:
            pos = random.randint(0, len(data) - 1)
            noise_byte = random.randint(0, 255)
            corrupted = data[:pos] + bytes([noise_byte]) + data[pos + 1:]
            self._log_operation("NOISE", "Signal corruption", 2,
                              position=pos,
                              original_byte=data[pos],
                              noise_byte=noise_byte)
            return corrupted
        return data

    def send(self, data: bytes) -> bytes:
        # Convert to Manchester encoding (simulated)
        self._log_operation("SEND", "Raw data", 0, input_bytes=data)
        encoded = b''.join(bytes([b, ~b & 0xFF]) for b in data)
        self._log_operation("SEND", "Manchester encoded", 1, encoded_bytes=encoded)
        
        result = self._simulate_noise(encoded)
        if result != encoded:
            self._log_operation("SEND", "Noise applied", 1, corrupted_bytes=result)
        return result

    def receive(self, data: bytes) -> bytes:
        # Decode Manchester encoding (simulated)
        self._log_operation("RECEIVE", "Raw signal", 0, signal=data)
        decoded = bytes(data[i] for i in range(0, len(data), 2))
        self._log_operation("RECEIVE", "Manchester decoded", 1, decoded_bytes=decoded)
        return decoded
