import socket
import argparse
import sys
import time
import threading
import json
import ipaddress


BUFFER_SIZE = 1024  # bytes
MESSAGE_ID_TTL = 600  # Time-to-live for message IDs in seconds (e.g., 10 minutes)

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='UDP Reliable Server')
    parser.add_argument('--listen-ip', required=True, help='IP address to bind the server.')
    parser.add_argument('--listen-port', type=int, required=True, help='Port number to listen on.')
    return parser.parse_args()

def create_socket(listen_ip, listen_port):
    """Create and bind a UDP socket."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((listen_ip, listen_port))
        print(f"Server listening on {listen_ip}:{listen_port}")
        return sock
    except socket.error as e:
        print(f"Failed to create or bind socket: {e}")
        sys.exit(1)

def receive_message(sock):
    """Receive a message."""
    try:
        data, addr = sock.recvfrom(BUFFER_SIZE)
        return data.decode(), addr
    except socket.error as e:
        print(f"Failed to receive data: {e}")
        return None, None

def send_ack(sock, addr, message_id):
    """Send an acknowledgment to the specified address."""
    try:
        ack_message = json.dumps({
            'status': 'ACK',
            'message_id': message_id
        })
        sock.sendto(ack_message.encode(), addr)
        print(f"Sent ACK for message ID {message_id} to {addr}")
    except socket.error as e:
        print(f"Failed to send ACK: {e}")

def cleanup_expired_message_ids(client_messages):
    """Periodically remove expired message IDs."""
    while True:
        current_time = time.time()
        for client_addr in list(client_messages.keys()):
            message_ids = client_messages[client_addr]
            # Remove expired message IDs
            message_ids[:] = [
                (msg_id, timestamp) for msg_id, timestamp in message_ids
                if current_time - timestamp < MESSAGE_ID_TTL
            ]
            # Remove client entry if no message IDs remain
            if not message_ids:
                del client_messages[client_addr]
        time.sleep(60)  # Sleep for 60 seconds before next cleanup

def run_server(listen_ip, listen_port):
    """Main server logic."""
    sock = create_socket(listen_ip, listen_port)
    client_messages = {}  # Dictionary to track message IDs and their timestamps per client

    # Start the cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_expired_message_ids, args=(client_messages,))
    cleanup_thread.daemon = True
    cleanup_thread.start()

    while True:
        message_str, client_addr = receive_message(sock)
        if message_str:
            try:
                # Parse the JSON message
                message_data = json.loads(message_str)
                message_id = message_data['message_id']
                content = message_data['content']

                # Get or create the list of message IDs for this client
                message_ids = client_messages.setdefault(client_addr, [])

                # Check if the message ID is already processed
                if not any(msg_id == message_id for msg_id, _ in message_ids):
                    print(f"Received new message from {client_addr}: {content}")
                    # Add message ID with current timestamp
                    message_ids.append((message_id, time.time()))
                    # Process the message here (e.g., save to database)
                else:
                    print(f"Duplicate message from {client_addr} (ID {message_id}), ignoring.")

                # Send ACK with message_id
                send_ack(sock, client_addr, message_id)

            except json.JSONDecodeError:
                print(f"Invalid JSON message from {client_addr}, ignoring.")
            except KeyError:
                print(f"Missing fields in message from {client_addr}, ignoring.")

    sock.close()

def main():
    args = parse_args()
    run_server(args.ip, args.port)

if __name__ == "__main__":
    main()
