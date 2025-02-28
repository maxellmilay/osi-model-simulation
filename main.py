from classes.device import Device

def simulate_communication():
    # Configuration for Device A
    device_a_config = {
        'mac_address': "00:11:22:33:44:55",  # Unique MAC for Device A
        'source_ip': "192.168.1.1",
        'destination_ip': "192.168.1.2",
        'session_id': "SESSION_A_123",
        'encryption_key': 0x42
    }

    # Configuration for Device B
    device_b_config = {
        'mac_address': "66:77:88:99:AA:BB",  # Unique MAC for Device B
        'source_ip': "192.168.1.2",
        'destination_ip': "192.168.1.1",
        'session_id': "SESSION_A_123",
        'encryption_key': 0x42
    }
    
    # Configuration for Device C
    device_c_config = {
        'mac_address': "CC:DD:EE:FF:00:11",  # Unique MAC for Device C
        'source_ip': "192.168.1.3",
        'destination_ip': "192.168.1.1",
        'session_id': "SESSION_A_123",
        'encryption_key': 0x42
    }

    # Create devices with their respective configurations
    device1 = Device("Device-A", device_a_config)
    device2 = Device("Device-B", device_b_config)
    device3 = Device("Device-C", device_c_config)

    # Get message from user
    message = input("Enter the message you want to send: ")
    
    print("\n=== Starting Communication Simulation ===")
    print(f"Original Message: {message}")
    
    # Device A sends message
    print("\n--- Device-A Sending Data ---")
    transmitted_data = device1.send_message(message)
    
    # Devices B and C attempt to receive the message
    print("\n--- Device-B Attempting to Receive Data ---")
    received_b = device2.receive_message(transmitted_data)
    
    print("\n--- Device-C Attempting to Receive Data ---")
    received_c = device3.receive_message(transmitted_data)
    
    print("\n=== Communication Results ===")
    print(f"Device-B received: {received_b if received_b else 'Message not for this device'}")
    print(f"Device-C received: {received_c if received_c else 'Message not for this device'}")

if __name__ == "__main__":
    simulate_communication()
