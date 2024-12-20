import socket
import argparse
import sys
import json
import uuid
import select
import ipaddress

BUFFER_SIZE = 1024  # bytes


def parse_args():
    parser = argparse.ArgumentParser(
        description="Client-server application using UDP sockets over the network"
    )
    parser.add_argument(
        "-i",
        "--target-ip",
        type=ipaddress.ip_address,
        help="Accepts the IP to connect to",
        required=True,
    )
    parser.add_argument(
        "-p",
        "--target-port",
        type=int,
        required=True,
        help="Accepts the port to connect to",
    )
    parser.add_argument(
        "-t", "--timeout", type=int, required=True, help="Timeout in seconds"
    )

    args = parser.parse_args()

    if args.target_port < 1 or args.target_port > 65535:
        parser.error("Port numbers must be between 1 and 65535.")

    if args.timeout <= 0:
        parser.error(f"Argument --timeout must be a positive integer bigger than 0.")

    return args


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
            if (
                ack_message.get("status") == "ACK"
                and ack_message.get("message_id") == message_id
            ):
                return True
            elif ack_message.get("status") == "ACK":
                print(
                    f"Received ACK with incorrect message_id: {ack_message.get('message_id')}"
                )
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
    target_addr = (str(target_ip), target_port)
    sock = create_socket()

    user_message = input("Enter message to send: ")

    # Generate a unique message ID
    message_id = str(uuid.uuid4())

    # Create the message as a JSON object
    message_payload = json.dumps({"message_id": message_id, "content": user_message})
    MAX_RETRIES = 5
    retries = 0

    while retries < MAX_RETRIES:
        send_message(sock, message_payload, target_addr)
        print("Message sent, waiting for ACK...")

        ack_received = receive_ack(sock, timeout, message_id)
        if ack_received:
            print("Received ACK from server.")
            break
        else:
            print("Retransmitting message...")

        retries += 1
    if retries == MAX_RETRIES:
        print(f"Failed to receive ACK after maximum {MAX_RETRIES} retries. Exiting.")

    sock.close()


def main():
    args = parse_args()
    run_client(args.target_ip, args.target_port, args.timeout)


if __name__ == "__main__":
    main()
