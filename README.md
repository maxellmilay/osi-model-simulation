# OSI Model Simulation

## Requirements:
- Python 3.12.0

## How to run:
1. Clone the repository
2. Run the script

```bash
python main.py
```

## How to use:
- Enter the message you want to send

```bash
Enter the message you want to send: Hello, World!
```

- The message will be sent from Device-A to Device-B and back

```bash
Original Message: Hello, World!
Final Received Message: Hello, World!
```

## Note
- You can play around the device configurations in the main file and test out multiple devices communicating with each other

## Project Overview

This project implements a detailed simulation of the OSI (Open Systems Interconnection) model, demonstrating how data travels through the seven layers of network communication. The simulation creates two virtual devices that can exchange messages while showing the exact processing that occurs at each layer.

### OSI Layer Implementation

The project implements all seven layers of the OSI model:

1. **Application Layer (Layer 7)**
   - Handles high-level protocols (HTTP simulation)
   - Creates structured requests and responses
   - Manages application-specific data formatting

2. **Presentation Layer (Layer 6)**
   - Handles data encryption/decryption
   - Performs data compression using zlib
   - Supports multiple data formats (JSON, Pickle, Plain text)
   - Manages data encoding and content type handling

3. **Session Layer (Layer 5)**
   - Manages communication sessions between devices
   - Handles session creation and validation
   - Tracks sequence numbers and timestamps
   - Maintains session state

4. **Transport Layer (Layer 4)**
   - Implements TCP-like segmentation
   - Manages sequence and acknowledgment numbers
   - Handles flow control with window sizing
   - Supports reliable data transfer

5. **Network Layer (Layer 3)**
   - Implements IPv4 packet handling
   - Manages source and destination IP addressing
   - Handles packet fragmentation
   - Includes TTL and protocol information

6. **Data Link Layer (Layer 2)**
   - Creates and processes Ethernet frames
   - Handles MAC addressing
   - Implements CRC error checking
   - Manages frame validation

7. **Physical Layer (Layer 1)**
   - Simulates physical data transmission
   - Implements Manchester encoding
   - Simulates signal noise and interference
   - Handles raw binary data

### Key Features

- **Complete Layer Isolation**: Each layer operates independently and communicates only with adjacent layers
- **Detailed Logging**: Comprehensive logging of operations at each layer
- **Error Simulation**: Physical layer includes configurable error rates to simulate real-world conditions
- **Data Integrity**: Implements checksums and CRC validation
- **Encryption**: Basic XOR encryption simulation at the presentation layer
- **Session Management**: Tracks and validates communication sessions
- **Protocol Support**: Simulated support for common protocols like HTTP

### Technical Implementation

The project uses Python's object-oriented features to create a modular and extensible system:

- Abstract base classes for consistent layer implementation
- Type hints for better code reliability
- Exception handling for robust error management
- Simulated network protocols and headers
- Binary data manipulation for realistic networking simulation

### Educational Value

This simulation serves as an educational tool to understand:
- How data is transformed as it moves through network layers
- The role and responsibility of each OSI layer
- Network protocol implementations
- Data encapsulation and decapsulation
- Error detection and handling in network communications
