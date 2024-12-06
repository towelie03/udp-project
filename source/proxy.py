import socket
import threading
import random
import argparse
import sys
import ipaddress
import json
import time
import select
from concurrent.futures import ThreadPoolExecutor

BUFFER_SIZE = 4096  # bytes


def parse_arguments():
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(description="UDP Proxy Server")
    parser.add_argument(
        "--listen-ip",
        type=ipaddress.ip_address,
        required=True,
        help="IP address to bind the proxy server.",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        required=True,
        help="Port number to listen for client packets.",
    )
    parser.add_argument(
        "--target-ip",
        type=ipaddress.ip_address,
        required=True,
        help="IP address of the server to forward packets to.",
    )
    parser.add_argument(
        "--target-port", type=int, required=True, help="Port number of the server."
    )
    parser.add_argument(
        "--client-drop",
        type=float,
        default=0.0,
        help="Drop chance (0 - 100 percent) for packets from the client.",
    )
    parser.add_argument(
        "--server-drop",
        type=float,
        default=0.0,
        help="Drop chance (0 - 100 percent) for packets from the server.",
    )
    parser.add_argument(
        "--client-delay",
        type=float,
        default=0.0,
        help="Delay chance (0 - 100 percent) for packets from the client.",
    )
    parser.add_argument(
        "--server-delay",
        type=float,
        default=0.0,
        help="Delay chance (0 - 100 percent) for packets from the server.",
    )
    parser.add_argument(
        "--client-delay-time",
        default="0",
        type=str,
        help="Delay time in milliseconds (fixed or range) for client packets.",
    )
    parser.add_argument(
        "--server-delay-time",
        default="0",
        type=str,
        help="Delay time in milliseconds (fixed or range) for server packets.",
    )

    args = parser.parse_args()

    for arg_name in ["listen_port", "target_port"]:
        value = getattr(args, arg_name)
        if value < 1 or value > 65535:
            parser.error("Port numbers must be between 1 and 65535.")

    # Validate drop and delay probabilities
    for arg_name in ["client_drop", "server_drop", "client_delay", "server_delay"]:
        value = getattr(args, arg_name)
        if not (0.0 <= value <= 100.0):
            parser.error(
                f'Argument --{arg_name.replace("_", "-")} must be between 0 and 100.'
            )

    # Parse delay times
    args.client_delay_time = parse_delay_time(
        args.client_delay_time, "--client-delay-time"
    )
    args.server_delay_time = parse_delay_time(
        args.server_delay_time, "--server-delay-time"
    )

    return args


def parse_delay_time(delay_time_str, arg_name):
    """
    Parse delay time string and return a tuple (min_delay, max_delay) in seconds.
    Supports fixed delays (e.g., "100") and ranges (e.g., "100-500").
    """
    try:
        if "-" in delay_time_str:
            min_str, max_str = delay_time_str.split("-", 1)
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
        raise ValueError(f"Invalid value for {arg_name}: {e}")


def settings_menu(params, lock, shutdown_event):
    """Interactive menu for changing proxy settings."""
    help_message_displayed = False
    while not shutdown_event.is_set():
        if not help_message_displayed:
            print("Proxy server is running.")
            print("Enter 'e' to edit settings")
            print("Enter 'q' or Ctrl+C to close server")
            help_message_displayed = True

        ready, _, _ = select.select([sys.stdin], [], [], 1.0)  # 1-second timeout
        if ready:
            user_input = sys.stdin.readline().strip().lower()  # Read the input
        else:
            if shutdown_event.is_set():
                break  # Exit if shutdown is triggered
            continue  # Timeout, go back to waiting

        if user_input == "e":
            help_message_displayed = False
            while True:
                with lock:
                    print("\n--- Proxy Settings ---")
                    print(
                        f"1. Client Drop Chance (current: {params['client_drop']} percent)"
                    )
                    print(
                        f"2. Server Drop Chance (current: {params['server_drop']} percent)"
                    )
                    print(
                        f"3. Client Delay Chance (current: {params['client_delay']} percent)"
                    )
                    print(
                        f"4. Server Delay Chance (current: {params['server_delay']} percent)"
                    )
                    print(
                        f"5. Client Delay Time (current: {params['client_delay_time'][0]*1000:.2f}-{params['client_delay_time'][1]*1000:.2f} ms)"
                    )
                    print(
                        f"6. Server Delay Time (current: {params['server_delay_time'][0]*1000:.2f}-{params['server_delay_time'][1]*1000:.2f} ms)"
                    )
                    print("Enter 'q' to return to the main menu.")

                choice = input("Choose an option (1-6): ").strip().lower()
                if choice == "q":
                    break
                elif choice in ["1", "2", "3", "4"]:
                    try:
                        value = float(input("Enter a new value (0-100): ").strip())
                        if 0 <= value <= 100:
                            with lock:
                                if choice == "1":
                                    params["client_drop"] = value
                                elif choice == "2":
                                    params["server_drop"] = value
                                elif choice == "3":
                                    params["client_delay"] = value
                                elif choice == "4":
                                    params["server_delay"] = value
                        else:
                            print("Value must be between 0 and 100.")
                    except ValueError:
                        print("Invalid input. Please enter a numeric value.")
                elif choice == "5":
                    value = input(
                        "Enter new Client Delay Time (ms, fixed or range, e.g., 100 or 100-500): "
                    ).strip()
                    try:
                        params["client_delay_time"] = parse_delay_time(
                            value, "--client-delay-time"
                        )
                    except ValueError as e:
                        print(e)
                elif choice == "6":
                    value = input(
                        "Enter new Server Delay Time (ms, fixed or range, e.g., 100 or 100-500): "
                    ).strip()
                    try:
                        params["server_delay_time"] = parse_delay_time(
                            value, "--server-delay-time"
                        )
                    except ValueError as e:
                        print(e)
                else:
                    print("Invalid option.")
        elif user_input == "q":
            shutdown_event.set()
            break


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


def simulate_delay(probability, delay_time_range, addr):
    """Simulate delay based on the given probability and delay time range."""
    if random.uniform(0, 100) < probability:
        delay = random.uniform(*delay_time_range)
        print(f"Delaying packet from {addr} by {delay * 1000:.2f} ms")
        time.sleep(delay)
        return delay
    return 0


def parse_packet(data, addr):
    """
    Parse the incoming packet.
    Returns the message_id if valid, else None.
    """
    try:
        message_str = data.decode()
        message_data = json.loads(message_str)
        message_id = message_data["message_id"]
        return message_id
    except (json.JSONDecodeError, KeyError):
        print(f"Malformed packet from {addr}, dropping packet.")
        return None


def handle_client_packet(
    data,
    client_address,
    server_address,
    proxy_socket,
    proxy_params,
    param_lock,
    message_id_to_client,
    message_id_lock,
):
    """Process and forward client packets to the server."""
    with param_lock:
        client_drop = proxy_params["client_drop"]
        client_delay = proxy_params["client_delay"]
        client_delay_time = proxy_params["client_delay_time"]

    # Simulate packet drop
    if simulate_drop(client_drop):
        print(f"Dropped packet from client {client_address}")
        return

    # Simulate delay
    simulate_delay(client_delay, client_delay_time, client_address)

    # Parse the packet to extract message_id
    message_id = parse_packet(data, client_address, role="client")
    if not message_id:
        return

    # Store the mapping of message_id to client_address with timestamp
    with message_id_lock:
        message_id_to_client[message_id] = (client_address, time.time())

    # Forward the packet to the server
    try:
        proxy_socket.sendto(data, server_address)
        print(
            f"Forwarded message_id {message_id} from client {client_address} to server {server_address}"
        )
    except socket.error as e:
        print(f"Error forwarding to server: {e}")


def handle_server_packet(
    data,
    server_address,
    proxy_socket,
    message_id_to_client,
    message_id_lock,
    proxy_params,
    param_lock,
):
    """Process and forward server packets to the appropriate client."""
    with param_lock:
        server_drop = proxy_params["server_drop"]
        server_delay = proxy_params["server_delay"]
        server_delay_time = proxy_params["server_delay_time"]

    # Simulate packet drop
    if simulate_drop(server_drop):
        print(f"Dropped packet from server {server_address}")
        return

    # Simulate delay
    simulate_delay(server_delay, server_delay_time, server_address)

    # Parse the packet to extract message_id
    message_id = parse_packet(data, server_address, role="server")
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
            print(
                f"Forwarded message_id {message_id} from server to client {client_address}"
            )
        except socket.error as e:
            print(f"Error forwarding to client {client_address}: {e}")
    else:
        print(
            f"No client mapping found for message_id {message_id}, cannot forward packet."
        )


def handle_packet(
    data,
    addr,
    server_address,
    proxy_socket,
    proxy_params,
    param_lock,
    message_id_to_client,
    message_id_lock,
):
    """Determine packet source and handle accordingly."""
    if addr == server_address:
        handle_server_packet(
            data,
            server_address,
            proxy_socket,
            message_id_to_client,
            message_id_lock,
            proxy_params,
            param_lock,
        )
    else:
        handle_client_packet(
            data,
            addr,
            server_address,
            proxy_socket,
            proxy_params,
            param_lock,
            message_id_to_client,
            message_id_lock,
        )


def cleanup_mappings(
    message_id_to_client,
    message_id_lock,
    timeout=600,
    cleanup_interval=60,
    shutdown_event=None,
):
    while not shutdown_event.is_set():
        time.sleep(cleanup_interval)
        current_time = time.time()
        with message_id_lock:
            stale_ids = [
                mid
                for mid, (addr, timestamp) in message_id_to_client.items()
                if current_time - timestamp > timeout
            ]
            for mid in stale_ids:
                del message_id_to_client[mid]
                print(f"Cleaned up stale message_id {mid}")


def main():
    """Entry point of the proxy."""
    args = parse_arguments()

    proxy_params = {
        "client_drop": args.client_drop,
        "server_drop": args.server_drop,
        "client_delay": args.client_delay,
        "server_delay": args.server_delay,
        "client_delay_time": args.client_delay_time,
        "server_delay_time": args.server_delay_time,
    }

    param_lock = threading.Lock()

    # Create the UDP socket
    proxy_socket = create_socket(args.listen_ip, args.listen_port)

    # Mapping of message_id to (client_address, timestamp)
    message_id_to_client = {}
    message_id_lock = threading.Lock()

    # Event to signal shutdown
    shutdown_event = threading.Event()

    # Start the cleanup thread
    cleanup_thread = threading.Thread(
        target=cleanup_mappings,
        args=(message_id_to_client, message_id_lock, 600, 60, shutdown_event),
        daemon=True,
    )
    cleanup_thread.start()

    settings_thread = threading.Thread(
        target=settings_menu,
        args=(proxy_params, param_lock, shutdown_event),
        daemon=True,
    )
    settings_thread.start()

    # Initialize ThreadPoolExecutor for managing worker threads
    with ThreadPoolExecutor(max_workers=100) as executor:
        try:
            while not shutdown_event.is_set():
                try:
                    data, addr = proxy_socket.recvfrom(BUFFER_SIZE)
                    # Submit the packet to the thread pool for handling
                    executor.submit(
                        handle_packet,
                        data,
                        addr,
                        (str(args.target_ip), args.target_port),
                        proxy_socket,
                        proxy_params,
                        param_lock,
                        message_id_to_client,
                        message_id_lock,
                    )
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
        finally:
            proxy_socket.close()  
            # Wait for all worker threads to finish
            executor.shutdown(wait=True)
            print("All worker threads have been terminated.")
            print("Proxy server has been shut down.")


if __name__ == "__main__":
    main()
