import socket
import threading
import random
import argparse
import sys
import ipaddress
import json
import time
from concurrent.futures import ThreadPoolExecutor

BUFFER_SIZE = 4096  # bytes

def parse_arguments():
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(description='UDP Proxy Server')
    parser.add_argument('--listen-ip', type=ipaddress.ip_address, required=True,
                        help='IP address to bind the proxy server.')
    parser.add_argument('--listen-port', type=int, required=True,
                        help='Port number to listen for client packets.')
    parser.add_argument('--target-ip', type=ipaddress.ip_address, required=True,
                        help='IP address of the server to forward packets to.')
    parser.add_argument('--target-port', type=int, required=True,
                        help='Port number of the server.')
    parser.add_argument('--client-drop', type=float, default=0.0,
                        help='Drop chance (0% - 100%) for packets from the client.')
    parser.add_argument('--server-drop', type=float, default=0.0,
                        help='Drop chance (0% - 100%) for packets from the server.')
    parser.add_argument('--client-delay', type=float, default=0.0,
                        help='Delay chance (0% - 100%) for packets from the client.')
    parser.add_argument('--server-delay', type=float, default=0.0,
                        help='Delay chance (0% - 100%) for packets from the server.')
    parser.add_argument('--client-delay-time', default="0", type=str,
                        help='Delay time in milliseconds (fixed or range) for client packets.')
    parser.add_argument('--server-delay-time', default="0", type=str,
                        help='Delay time in milliseconds (fixed or range) for server packets.')

    args = parser.parse_args()

    # Validate drop and delay probabilities
    for arg_name in ['client_drop', 'server_drop', 'client_delay', 'server_delay']:
        value = getattr(args, arg_name)
        if not (0.0 <= value <= 100.0):
            parser.error(f'Argument --{arg_name.replace("_", "-")} must be between 0 and 100.')

    # Parse delay times
    args.client_delay_time = parse_delay_time(args.client_delay_time, parser, '--client-delay-time')
    args.server_delay_time = parse_delay_time(args.server_delay_time, parser, '--server-delay-time')

    return args

def parse_delay_time(delay_time_str, parser, arg_name):
    """
    Parse delay time string and return a tuple (min_delay, max_delay) in seconds.
    Supports fixed delays (e.g., "100") and ranges (e.g., "100-500").
    """
    try:
        if '-' in delay_time_str:
            min_str, max_str = delay_time_str.split('-', 1)
            min_delay_ms = int(min_str.strip())
            max_delay_ms = int(max_str.strip())
            if min_delay_ms > max_delay_ms:
                raise ValueError("Minimum delay cannot be greater than maximum delay.")
            if min_delay_ms < 0 or max_delay_ms < 0:
                raise ValueError("Delay times must be non-negative.")
            return (min_delay_ms / 1000.0, max_delay_ms / 1000.0)
        else:
            delay_ms = int(delay_time_str.strip())
            if delay_ms < 0:
                raise ValueError("Delay time must be non-negative.")
            return (delay_ms / 1000.0, delay_ms / 1000.0)
    except ValueError as e:
        parser.error(f'Invalid value for {arg_name}: {e}')

def create_socket(listen_ip, listen_port):
    """Create and bind a UDP socket."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((str(listen_ip), listen_port))
        sock.settimeout(1.0)  # Set timeout to allow periodic shutdown checks
        print(f"Proxy server listening on {listen_ip}:{listen_port}")
        return sock
    except socket.error as e:
        print(f"Failed to create or bind socket: {e}")
        sys.exit(1)

def simulate_drop(probability):
    """Determine whether to drop a packet based on the given probability."""
    return random.uniform(0, 100) < probability

def simulate_delay(probability, delay_time_range):
    """Simulate delay based on the given probability and delay time range."""
    if random.uniform(0, 100) < probability:
        delay = random.uniform(*delay_time_range)
        print(f"Delaying packet by {delay * 1000:.2f} ms")
        time.sleep(delay)
        return delay
    return 0

def parse_packet(data, addr, role='client'):
    """
    Parse the incoming packet.
    Returns the message_id if valid, else None.
    """
    try:
        message_str = data.decode()
        message_data = json.loads(message_str)
        message_id = message_data['message_id']
        return message_id
    except (json.JSONDecodeError, KeyError):
        print(f"Malformed packet from {addr}, dropping packet.")
        return None

def handle_client_packet(data, client_address, server_address, proxy_socket, args, message_id_to_client, message_id_lock):
    """Process and forward client packets to the server."""
    # Simulate packet drop
    if simulate_drop(args.client_drop):
        print(f"Dropped packet from client {client_address}")
        return

    # Simulate delay
    simulate_delay(args.client_delay, args.client_delay_time)

    # Parse the packet to extract message_id
    message_id = parse_packet(data, client_address, role='client')
    if not message_id:
        return

    # Store the mapping of message_id to client_address with timestamp
    with message_id_lock:
        message_id_to_client[message_id] = (client_address, time.time())

    # Forward the packet to the server
    try:
        proxy_socket.sendto(data, server_address)
        print(f"Forwarded message_id {message_id} from client {client_address} to server {server_address}")
    except socket.error as e:
        print(f"Error forwarding to server: {e}")

def handle_server_packet(data, server_address, proxy_socket, message_id_to_client, message_id_lock, args):
    """Process and forward server packets to the appropriate client."""
    # Simulate packet drop
    if simulate_drop(args.server_drop):
        print(f"Dropped packet from server {server_address}")
        return

    # Simulate delay
    simulate_delay(args.server_delay, args.server_delay_time)

    # Parse the packet to extract message_id
    message_id = parse_packet(data, server_address, role='server')
    if not message_id:
        return

    # Retrieve the client's address using message_id
    with message_id_lock:
        mapping = message_id_to_client.get(message_id)
        if mapping:
            client_address, _ = mapping
        else:
            client_address = None

    if client_address:
        # Forward the packet to the client
        try:
            proxy_socket.sendto(data, client_address)
            print(f"Forwarded message_id {message_id} from server to client {client_address}")
            # Remove the mapping after forwarding
            with message_id_lock:
                del message_id_to_client[message_id]
        except socket.error as e:
            print(f"Error forwarding to client {client_address}: {e}")
    else:
        print(f"No client mapping found for message_id {message_id}, cannot forward packet.")

def handle_packet(data, addr, server_address, proxy_socket, args, message_id_to_client, message_id_lock):
    """Determine packet source and handle accordingly."""
    if addr == server_address:
        handle_server_packet(data, server_address, proxy_socket, message_id_to_client, message_id_lock, args)
    else:
        handle_client_packet(data, addr, server_address, proxy_socket, args, message_id_to_client, message_id_lock)

def cleanup_mappings(message_id_to_client, message_id_lock, timeout=600, cleanup_interval=60, shutdown_event=None):
    while not shutdown_event.is_set():
        time.sleep(cleanup_interval)
        current_time = time.time()
        with message_id_lock:
            stale_ids = [mid for mid, (addr, timestamp) in message_id_to_client.items()
                         if current_time - timestamp > timeout]
            for mid in stale_ids:
                del message_id_to_client[mid]
                print(f"Cleaned up stale message_id {mid}")

def main():
    """Entry point of the proxy."""
    args = parse_arguments()

    # Create the UDP socket
    proxy_socket = create_socket(args.listen_ip, args.listen_port)

    # Mapping of message_id to (client_address, timestamp)
    message_id_to_client = {}
    message_id_lock = threading.Lock()

    # List to keep track of worker threads
    worker_threads = []
    
    # Event to signal shutdown
    shutdown_event = threading.Event()

    # Start the cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_mappings, args=(message_id_to_client, message_id_lock), daemon=True)
    cleanup_thread.start()

    print("Proxy server is running. Press Ctrl+C to stop.")

    # Initialize ThreadPoolExecutor for managing worker threads
    with ThreadPoolExecutor(max_workers=100) as executor:
        try:
            while not shutdown_event.is_set():
                try:
                    data, addr = proxy_socket.recvfrom(BUFFER_SIZE)
                    # Submit the packet to the thread pool for handling
                    executor.submit(handle_packet, data, addr, (str(args.target_ip), args.target_port),
                                    proxy_socket, args, message_id_to_client, message_id_lock)
                except socket.timeout:
                    continue  # Allows checking the shutdown_event
                except socket.error as e:
                    if shutdown_event.is_set():
                        break  # Expected error when socket is closed
                    else:
                        print(f"Socket error: {e}")
        except KeyboardInterrupt:
            print("\nKeyboard interrupt received. Shutting down proxy...")
            shutdown_event.set()
            proxy_socket.close()  # This will unblock recvfrom
        finally:
            # Wait for all worker threads to finish
            executor.shutdown(wait=True)
            print("All worker threads have been terminated.")
            print("Proxy server has been shut down.")

if __name__ == "__main__":
    main()
