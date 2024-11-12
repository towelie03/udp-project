import socket
import argparse
import sys
import ipaddress
import time

LINE_LEN = 4096

def parse_args():
    parser = argparse.ArgumentParser(description="Client-server application using UDP sockets over the network")
    parser.add_argument('-i', '--ip', type=ipaddress.ip_address, help="Accepts the IP to connect to", required=True)
    parser.add_argument('-p', '--port', type=int, required=True, help="Accepts the port to connect to")
    parser.add_argument('-t', '--timeout', type=int, required=True, help="Timeout in seconds")
    return parser.parse_args()

def connect_to_server(HOST, PORT):
    connection = (HOST, PORT)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print(f"Socket created and connected to {HOST}:{PORT}")
        return sock, connection
    except Exception as e:
        print(f"Error: Unable to create server socket: {e}")
        sys.exit(1)

def send_message(sock, connection, message, timeout):
    try:
        sock.sendto(message.encode('utf-8'), connection)
        sock.settimeout(timeout)
        try:
            ack, _ = sock.recvfrom(LINE_LEN)
            if ack.decode('utf-8') == "ACK":
                print("Acknowledgment received")
                return True
        except socket.timeout:
            print("Timeout: No acknowledgment received, retrying...")
            return False
    except Exception as e:
        print(f"Error: Unable to send message: {e}")
        return False

def main():
    args = parse_args()
    HOST = str(args.ip)
    PORT = args.port
    TIMEOUT = time.sleep(args.timeout / 1000.0)  # Convert milliseconds to seconds

    sock, connection = connect_to_server(HOST, PORT)
    
    try:
        print("Enter message to send:")
        while True:
            message = input("")
            if not message:
                print("No message entered, exiting.")
                break

            while not send_message(sock, connection, message, TIMEOUT):
                print("Retrying...")
    except KeyboardInterrupt:
        print("Exiting...")
    finally:
        sock.close()

if __name__ == "__main__":
    main()

