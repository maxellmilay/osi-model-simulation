from classes.device import Device

def simulate_communication():
    # Configuration for Device A
    device_a_config = {
        'mac_address': "AA:BB:CC:DD:EE:FF",
        'source_ip': "192.168.1.1",
        'destination_ip': "192.168.1.2",
        'session_id': "SESSION_A_123",
        'encryption_key': 0x42
    }

    # Configuration for Device B - Note the matching MAC address and reversed IPs
    device_b_config = {
        'mac_address': "AA:BB:CC:DD:EE:FF",  # Same as Device A to receive the frame
        'source_ip': "192.168.1.2",
        'destination_ip': "192.168.1.1",
        'session_id': "SESSION_A_123",  # Same session ID to maintain the session
        'encryption_key': 0x42  # Same encryption key to decrypt the message
    }

    # Create two devices with their respective configurations
    device1 = Device("Device-A", device_a_config)
    device2 = Device("Device-B", device_b_config)

    # Get message from user
    message = input("Enter the message you want to send: ")
    
    print("\n=== Starting Communication Simulation ===")
    print(f"Original Message: {message}")
    
    print("\n--- Device-A Sending Data ---")
    transmitted_data = device1.send_message(message)
    
    print("\n--- Device-B Receiving Data ---")
    received_message = device2.receive_message(transmitted_data)
    
    print("\n=== Communication Summary ===")
    print(f"Original Message: {message}")
    print(f"Final Received Message: {received_message}")
    print("\n=== Simulation Complete ===")

if __name__ == "__main__":
    simulate_communication()
