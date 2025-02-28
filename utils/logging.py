import logging

class CustomFormatter(logging.Formatter):
    def format(self, record):
        # Remove the INFO/ERROR prefix and just use the message
        return record.getMessage()

# Create logger
logger = logging.getLogger('osi_model')
handler = logging.StreamHandler()

# Create and set custom formatter
formatter = CustomFormatter()
handler.setFormatter(formatter)

# Add handler to logger
logger.addHandler(handler)
logger.setLevel(logging.INFO)

def log_layer(layer_name, operation, message, indent_level=0):
    """
    Log a formatted message for an OSI layer.
    
    Args:
        layer_name (str): Name of the OSI layer
        operation (str): Operation being performed (e.g., "SEND" or "RECEIVE")
        message (str): The message or data being processed
        indent_level (int): Indentation level for visual hierarchy
    """
    indent = "│   " * indent_level
    layer_prefix = "├─"
    
    # Format the header and data differently
    if "|" in str(message):
        header, payload = str(message).split("|", 1)
        formatted_message = f"{header}\n{indent}│   └─ Payload: {payload}"
    else:
        formatted_message = str(message)

    # Create a visually distinct separator for each layer
    separator = "│" if indent_level > 0 else ""
    
    log_message = f"{indent}{layer_prefix} {layer_name} {operation}\n{indent}│   {formatted_message}"
    
    if operation == "ERROR":
        logger.error(log_message)
    else:
        logger.info(log_message) 