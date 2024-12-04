import socket
import argparse
import sys
import time
import threading
import json
import ipaddress


BUFFER_SIZE = 1024  # bytes
MESSAGE_ID_TTL = 600  # Time-to-live for message IDs in seconds (e.g., 10 minutes)
CLEANING_PERIOD = 60


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="UDP Reliable Server")
    parser.add_argument(
        "--listen-ip", type=ipaddress.ip_address,required=True, help="IP address to bind the server."
    )
    parser.add_argument(
        "--listen-port", type=int, required=True, help="Port number to listen on."
    )
    args = parser.parse_args()
    
    if args.listen_port < 1 or args.listen_port > 65535:
        parser.error("Port numbers must be between 1 and 65535.")
        
    return args


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
        ack_message = json.dumps({"status": "ACK", "message_id": message_id})
        sock.sendto(ack_message.encode(), addr)
        print(f"Sent ACK for message ID {message_id} to {addr}")
    except socket.error as e:
        print(f"Failed to send ACK: {e}")


def cleanup_expired_message_ids(client_messages, shutdown_event):
    """Periodically remove expired message IDs."""
    while not shutdown_event.is_set():
        current_time = time.time()
        for client_addr in list(client_messages.keys()):
            message_ids = client_messages[client_addr]
            message_ids[:] = [
                (msg_id, timestamp)
                for msg_id, timestamp in message_ids
                if current_time - timestamp < MESSAGE_ID_TTL
            ]
            if not message_ids:
                del client_messages[client_addr]
        shutdown_event.wait(
            CLEANING_PERIOD
        )  # Sleep for 60 seconds or until shutdown_event is set


def run_server(listen_ip, listen_port, shutdown_event):
    """Main server logic."""
    sock = create_socket(listen_ip, listen_port)
    client_messages = {}

    # Start the cleanup thread
    cleanup_thread = threading.Thread(
        target=cleanup_expired_message_ids, args=(client_messages, shutdown_event)
    )
    cleanup_thread.daemon = True
    cleanup_thread.start()

    try:
        while not shutdown_event.is_set():
            message_str, client_addr = receive_message(sock)
            if message_str:
                try:
                    message_data = json.loads(message_str)
                    message_id = message_data["message_id"]
                    content = message_data["content"]

                    message_ids = client_messages.setdefault(client_addr, [])

                    if not any(msg_id == message_id for msg_id, _ in message_ids):
                        print(f"Received new message from {client_addr}: {content}")
                        message_ids.append((message_id, time.time()))
                    else:
                        print(
                            f"Duplicate message from {client_addr} (ID {message_id}), ignoring."
                        )

                    send_ack(sock, client_addr, message_id)
                except json.JSONDecodeError:
                    print(f"Invalid JSON message from {client_addr}, ignoring.")
                except KeyError:
                    print(f"Missing fields in message from {client_addr}, ignoring.")
    finally:
        shutdown_event.set()  # Signal threads to stop
        cleanup_thread.join()  # Wait for the cleanup thread to finish
        sock.close()
        print("Server shut down gracefully.")


def main():
    args = parse_args()

    # Event to signal shutdown
    shutdown_event = threading.Event()
    try:
        run_server(args.listen_ip, args.listen_port, shutdown_event)
    except KeyboardInterrupt:
        print("\nShutdown signal received.")
        shutdown_event.set()  # Signal shutdown to threads


if __name__ == "__main__":
    main()
