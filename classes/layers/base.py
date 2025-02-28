from abc import ABC, abstractmethod
import json

from utils.logging import log_layer


class OSILayer(ABC):
    def _log_operation(self, operation: str, message: str, indent_level: int = 0, **extra):
        details = []
        for key, value in extra.items():
            if isinstance(value, bytes):
                value = value.hex()
            elif isinstance(value, dict):
                value = json.dumps(value, indent=2)
            details.append(f"{key}: {value}")
        
        full_message = f"{message}"
        if details:
            full_message += f" | {', '.join(details)}"
        
        log_layer(self.layer_name, operation, full_message, indent_level)

    @abstractmethod
    def send(self, data: bytes) -> bytes:
        """Process and send data to the next lower layer."""
        pass

    @abstractmethod
    def receive(self, data: bytes) -> bytes:
        """Process and receive data from the lower layer."""
        pass
