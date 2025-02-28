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
        self._log_operation("SEND", "Raw data", 0, input_bytes=data)
        
        # Simulate noise/interference
        data = self._simulate_noise(data)
        
        self._log_operation("SEND", "Processed data", 1, processed_bytes=data)
        return data

    def receive(self, data: bytes) -> bytes:
        self._log_operation("RECEIVE", "Raw data", 0, input_bytes=data)
        return data
