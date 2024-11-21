import socket
import argparse
import sys
import json
import uuid
import select
import ipaddress

BUFFER_SIZE = 1024  # bytes

def parse_args():
    parser = argparse.ArgumentParser(description="Client-server application using UDP sockets over the network")
    parser.add_argument('-i', '--ip', type=ipaddress.ip_address, help="Accepts the IP to connect to", required=True)
    parser.add_argument('-p', '--port', type=int, required=True, help="Accepts the port to connect to")
    parser.add_argument('-t', '--timeout', type=int, required=True, help="Timeout in seconds")
    return parser.parse_args()

def create_socket():
    """Create a UDP socket."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return sock
    except socket.error as e:
        print(f"Failed to create socket: {e}")
        sys.exit(1)

def send_message(sock, message, addr):
    """Send a message to the specified address."""
    try:
        sock.sendto(message.encode(), addr)
        print(f"Message sent to {addr}")
    except socket.error as e:
        print(f"Failed to send message: {e}")
        sys.exit(1)

def receive_ack(sock, timeout, message_id):
    """Wait for an acknowledgment with a timeout using select."""
    try:
        # Prepare to use select
        readable, _, _ = select.select([sock], [], [], timeout)
        if readable:
            data, _ = sock.recvfrom(BUFFER_SIZE)
            ack_data = data.decode()
            ack_message = json.loads(ack_data)
            if ack_message.get('status') == 'ACK' and ack_message.get('message_id') == message_id:
                return True
            elif ack_message.get('status') == 'ACK':
                print(f"Received ACK with incorrect message_id: {ack_message.get('message_id')}")
                return False
            else:
                print(f"Unexpected response returned from server")
                return False
        else:
            print("Timeout waiting for ACK.")
            return False
    except (socket.error, json.JSONDecodeError) as e:
        print(f"Failed to receive ACK: {e}")
        return False

def run_client(target_ip, target_port, timeout):
    """Main client logic."""
    target_addr = (target_ip, target_port)
    sock = create_socket()

    user_message = input("Enter message to send: ")

    # Generate a unique message ID
    message_id = str(uuid.uuid4())

    # Create the message as a JSON object
    message_payload = json.dumps({
        'message_id': message_id,
        'content': user_message
    })

    while True:
        send_message(sock, message_payload, target_addr)
        print("Message sent, waiting for ACK...")

        ack_received = receive_ack(sock, timeout, message_id)
        if ack_received:
            print("Received ACK from server.")
            break
        else:
            print("Retransmitting message...")

    sock.close()


def main():
    args = parse_args()
    run_client(args.ip, args.port, args.timeout)

if __name__ == "__main__":
    main()
