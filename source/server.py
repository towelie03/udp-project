import socket
import argparse
import sys
import ipaddress

LINE_LEN = 4096

def parse_args():
    parser = argparse.ArgumentParser(description="Client-server application using UDP sockets over the network")
    parser.add_argument('-i', '--ip', type=ipaddress.ip_address, help="Accepts the IP to listen on (default: 0.0.0.0)", default='0.0.0.0')
    parser.add_argument('-p', '--port', type=int, required=True, help="Accepts the port to listen on")
    return parser.parse_args()

def setup_server_socket(HOST, PORT):
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_sock.bind((HOST, PORT))
        print(f"Server listening on {HOST}:{PORT}")
        return server_sock
    except Exception as e:
        print(f"Error: Unable to create server socket: {e}")
        sys.exit(1)

def handle_client(server_sock):
    while True:
        try:
            data, client_addr = server_sock.recvfrom(LINE_LEN)
            message = data.decode('utf-8')
            print(f"Received message from {client_addr}: {message}")
            send_reply(server_sock, client_addr, "ACK")
        except Exception as e:
            print(f"Error: Unable to handle client: {e}")

def send_reply(server_sock, client_addr, reply):
    try:
        server_sock.sendto(reply.encode('utf-8'), client_addr)
    except Exception as e:
        print(f"Error: Unable to send response: {e}")

def main():
    args = parse_args()
    HOST = str(args.ip)
    PORT = args.port

    server_sock = setup_server_socket(HOST, PORT)
    try:
        handle_client(server_sock)
    except KeyboardInterrupt:
        print("Exiting...")
    finally:
        server_sock.close()
        sys.exit(0)

if __name__ == "__main__":
    main()

