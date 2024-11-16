import socket
import argparse
import sys
import time
import random
import threading

LINE_LEN = 4096

def parse_args():
    parser = argparse.ArgumentParser(description="Unreliable Network Proxy Server")
    parser.add_argument('--listen-ip', type=str, required=True, help="IP address to bind the proxy server.")
    parser.add_argument('--listen-port', type=int, required=True, help="Port number to listen for client packets.")
    parser.add_argument('--target-ip', type=str, required=True, help="IP address of the server to forward packets to.")
    parser.add_argument('--target-port', type=int, required=True, help="Port number of the server.")
    parser.add_argument('--client-drop', type=float, required=True, help="Drop chance (0% - 100%) for packets from the client.")
    parser.add_argument('--server-drop', type=float, required=True, help="Drop chance (0% - 100%) for packets from the server.")
    parser.add_argument('--client-delay', type=float, required=True, help="Delay chance (0% - 100%) for packets from the client.")
    parser.add_argument('--server-delay', type=float, required=True, help="Delay chance (0% - 100%) for packets from the server.")
    parser.add_argument('--client-delay-time', type=str, required=True, help="Delay time in milliseconds (fixed or range) for packets from the client.")
    parser.add_argument('--server-delay-time', type=str, required=True, help="Delay time in milliseconds (fixed or range) for packets from the server.")
    return parser.parse_args()

def parse_delay_time(delay_time_str):
    if '-' in delay_time_str:
        min_delay, max_delay = map(int, delay_time_str.split('-'))
        return random.randint(min_delay, max_delay)
    return int(delay_time_str)

def simulate_unreliable_network(sock, listen_addr, target_addr, client_drop, server_drop, client_delay, server_delay, client_delay_time, server_delay_time):
    def handle_client_to_server():
        while True:
            data, client_addr = sock.recvfrom(LINE_LEN)
            if random.random() < client_drop / 100.0:
                print("Dropping packet from client to server")
                continue
            if random.random() < client_delay / 100.0:
                delay_time = parse_delay_time(client_delay_time)
                print(f"Delaying packet from client to server by {delay_time} ms")
                time.sleep(delay_time / 1000.0)
            sock.sendto(data, target_addr)

    def handle_server_to_client():
        while True:
            data, server_addr = sock.recvfrom(LINE_LEN)
            if random.random() < server_drop / 100.0:
                print("Dropping packet from server to client")
                continue
            if random.random() < server_delay / 100.0:
                delay_time = parse_delay_time(server_delay_time)
                print(f"Delaying packet from server to client by {delay_time} ms")
                time.sleep(delay_time / 1000.0)
            sock.sendto(data, client_addr)

    threading.Thread(target=handle_client_to_server, daemon=True).start()
    threading.Thread(target=handle_server_to_client, daemon=True).start()

def main():
    args = parse_args()
    listen_addr = (args.listen_ip, args.listen_port)
    target_addr = (args.target_ip, args.target_port)
    
    client_drop = args.client_drop
    server_drop = args.server_drop
    client_delay = args.client_delay
    server_delay = args.server_delay
    client_delay_time = args.client_delay_time
    server_delay_time = args.server_delay_time

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(listen_addr)
        print(f"Proxy server listening on {args.listen_ip}:{args.listen_port}")
    except Exception as e:
        print(f"Error: Unable to create and bind socket: {e}")
        sys.exit(1)

    simulate_unreliable_network(sock, listen_addr, target_addr, client_drop, server_drop, client_delay, server_delay, client_delay_time, server_delay_time)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Exiting...")
    finally:
        sock.close()
        sys.exit(0)

if __name__ == "__main__":
    main()

