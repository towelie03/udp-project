import socket
import asyncio
import random
import argparse
import sys
import ipaddress
import json

BUFFER_SIZE = 4096  # bytes

def parse_arguments():
    """Parse command-line arguments."""
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

    # Validation
    for arg_name in ['client_drop', 'server_drop', 'client_delay', 'server_delay']:
        value = getattr(args, arg_name)
        if not (0.0 <= value <= 100.0):
            parser.error(f'Argument --{arg_name.replace("_", "-")} must be between 0 and 100.')

    # Parse delay times
    args.client_delay_time = parse_delay_time(args.client_delay_time, parser, '--client-delay-time')
    args.server_delay_time = parse_delay_time(args.server_delay_time, parser, '--server-delay-time')

    return args

def parse_delay_time(delay_time_str, parser, arg_name):
    """Parse delay time string and return delay time in seconds as a tuple (min_delay, max_delay)."""
    try:
        if '-' in delay_time_str:
            # Range specified
            min_str, max_str = delay_time_str.split('-', 1)
            min_delay_ms = int(min_str.strip())
            max_delay_ms = int(max_str.strip())
            if min_delay_ms > max_delay_ms:
                raise ValueError("Minimum delay cannot be greater than maximum delay.")
            if min_delay_ms < 0 or max_delay_ms < 0:
                raise ValueError("Delay times must be non-negative.")
            return (min_delay_ms / 1000.0, max_delay_ms / 1000.0)
        else:
            # Fixed delay
            delay_ms = int(delay_time_str.strip())
            if delay_ms < 0:
                raise ValueError("Delay time must be non-negative.")
            return (delay_ms / 1000.0, delay_ms / 1000.0)
    except ValueError as e:
        parser.error(f'Invalid value for {arg_name}: {e}')

def create_socket(listen_ip, listen_port):
    """Create and bind a UDP socket compatible with asyncio."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((str(listen_ip), listen_port))
        sock.setblocking(False)  # Make socket non-blocking
        print(f"Proxy server listening on {listen_ip}:{listen_port}")
        return sock
    except socket.error as e:
        print(f"Failed to create or bind socket: {e}")
        sys.exit(1)

async def handle_messages(proxy_socket, server_address, args, message_id_to_client, message_id_lock):
    loop = asyncio.get_event_loop()
    while True:
        try:
            data, addr = await loop.sock_recvfrom(proxy_socket, BUFFER_SIZE)
            if addr == server_address:
                await handle_server_message(proxy_socket, data, addr, args, message_id_to_client, message_id_lock)
            else:
                await handle_client_message(proxy_socket, data, addr, server_address, args, message_id_to_client, message_id_lock)
        except Exception as e:
            print(f"Error handling message: {e}")

async def handle_client_message(proxy_socket, data, client_address, server_address, args, message_id_to_client, message_id_lock):
    # Simulate drop
    if random.uniform(0, 100) < args.client_drop:
        print(f"Dropped packet from client {client_address}")
        return

    # Simulate delay
    if random.uniform(0, 100) < args.client_delay:
        delay = random.uniform(*args.client_delay_time)
        print(f"Delaying packet from client {client_address} by {delay * 1000:.2f} ms")
        await asyncio.sleep(delay)
    
    await forward_to_server(proxy_socket, data, server_address, client_address, message_id_to_client, message_id_lock)

async def forward_to_server(proxy_socket, data, server_address, client_address, message_id_to_client, message_id_lock):
    try:
        # Extract message_id from the client's message
        message_str = data.decode()
        message_data = json.loads(message_str)
        message_id = message_data['message_id']

        # Store the mapping of message_id to client_address
        async with message_id_lock:
            message_id_to_client[message_id] = client_address

        loop = asyncio.get_event_loop()
        await loop.sock_sendto(proxy_socket, data, server_address)
        print(f"Forwarded message_id {message_id} from client {client_address} to server {server_address}")
    except Exception as e:
        print(f"Error forwarding to server: {e}")

async def handle_server_message(proxy_socket, data, server_address, args, message_id_to_client, message_id_lock):
    # Simulate drop
    if random.uniform(0, 100) < args.server_drop:
        print(f"Dropped packet from server {server_address}")
        return

    # Simulate delay
    if random.uniform(0, 100) < args.server_delay:
        delay = random.uniform(*args.server_delay_time)
        print(f"Delaying packet from server by {delay * 1000:.2f} ms")
        await asyncio.sleep(delay)
    
    await forward_to_client(proxy_socket, data, message_id_to_client, message_id_lock)

async def forward_to_client(proxy_socket, data, message_id_to_client, message_id_lock):
    try:
        # Extract message_id from the server's message
        message_str = data.decode()
        message_data = json.loads(message_str)
        message_id = message_data['message_id']

        # Retrieve the client's address using message_id
        async with message_id_lock:
            client_address = message_id_to_client.get(message_id)

        if client_address:
            loop = asyncio.get_event_loop()
            await loop.sock_sendto(proxy_socket, data, client_address)
            print(f"Forwarded message_id {message_id} from server to client {client_address}")

            # Optionally, remove the mapping if it's no longer needed
            async with message_id_lock:
                del message_id_to_client[message_id]
        else:
            print(f"No client mapping found for message_id {message_id}")
    except Exception as e:
        print(f"Error forwarding to client: {e}")

def main():
    args = parse_arguments()

    # Create sockets
    proxy_socket = create_socket(args.listen_ip, args.listen_port)
    server_address = (str(args.target_ip), args.target_port)

    # Mapping of message_id to client address
    message_id_to_client = {}
    message_id_lock = asyncio.Lock()  # Use asyncio lock

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(
            handle_messages(proxy_socket, server_address, args, message_id_to_client, message_id_lock)
        )
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()

if __name__ == "__main__":
    main()
