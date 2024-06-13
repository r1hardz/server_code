import socket
import threading
from cryptography.hazmat.primitives import serialization

HOST = '0.0.0.0'
PORT = 12345

# start server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(5)

print(f'Server is listening for connections...')

rooms = {}
clients = []
lock = threading.Lock()

def broadcast_message(message, room_id, sender):
    with lock:
        # log the message broadcasting event
        print(f"Broadcasting message in room {room_id} from {sender.getpeername()}")
         # if the room exists and has clients
        if room_id in rooms and rooms[room_id]['clients']:
                for client in rooms[room_id]['clients']:
                    if client != sender:
                        try:
                            print(f"Sending message to {client.getpeername()[0]}:{client.getpeername()[1]}")
                            client.send(message)
                        except Exception as e:
                            print(f'Error broadcasting message to {client}: {e}')
                            client.close()
                            rooms[room_id]['clients'].remove(client)
                            # remove the client's public key if it exists
                            if client in rooms[room_id]['public_keys']:
                                del rooms[room_id]['public_keys'][client]
        else:
            print(f"Room {room_id} does not exist or is empty.")

def broadcast_public_keys(room_id, new_client=None, leaving_client=None):
    with lock:
        if room_id in rooms:
            # broadcast public keys to all clients in the room
            print(f"Broadcasting public keys in room {room_id}")
            for client in rooms[room_id]['clients']:
                for other_client, other_public_key in rooms[room_id]['public_keys'].items():
                    if other_client != client:
                        try:
                            # send the public key to the client
                            print(f"Sending public key from {other_client.getpeername()[0]}:{other_client.getpeername()[1]} to {client.getpeername()[0]}:{client.getpeername()[1]}")
                            # convert the public key to bytes
                            public_key_bytes = other_public_key.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            )
                            client.send(public_key_bytes)
                        except Exception as e:
                            print(f'Error broadcasting message/public key to {client.getpeername()}: {e}')
                            client.close()
                            rooms[room_id]['clients'].remove(client)
                            del rooms[room_id]['public_keys'][client]

        # delete the leaving client's public key from the room's public keys
        if leaving_client:
            if room_id in rooms and leaving_client in rooms[room_id]['public_keys']:
                del rooms[room_id]['public_keys'][leaving_client]
                
def leave_room(client, room_id):
    with lock:
        if room_id in rooms and client in rooms[room_id]['clients']:
            print(f"Client {client.getpeername()} leaving room {room_id}")
            # remove the client from the rooms client list
            rooms[room_id]['clients'].remove(client)

            # remove the client's public key from the room
            if client in rooms[room_id]['public_keys']:
                del rooms[room_id]['public_keys'][client]

            # if the room has no more clients, delete the room
            if not rooms[room_id]['clients']:
                del rooms[room_id]  
                print(f"Room {room_id} is now empty and has been removed.")
            else:
                # notify remaining clients in the room that the a users has left
                remaining_clients = rooms[room_id]['clients']
                for remaining_client in remaining_clients:
                    if remaining_client != client:
                        try:
                            remaining_client.send(f"CLIENT_LEFT|{client.getpeername()[0]}|{client.getpeername()[1]}".encode())
                            print(f"Notified {remaining_client.getpeername()} that {client.getpeername()} left the room")
                        except Exception as e:
                            print(f"Error notifying {remaining_client.getpeername()} about client {client.getpeername()} leaving: {e}")
            try:
                client.send(f"LEAVE|{room_id}|confirmation".encode()) 
                print(f"Sent leave confirmation to {client.getpeername()}")
            except Exception as e:
                print(f"Error sending leave confirmation to {client.getpeername()}: {e}")
            print(f"Client {client.getpeername()} has left the room {room_id}")
        else:
            print(f"Client {client.getpeername()} tried to leave a non-existent or empty room {room_id}")

def handle_client(client):
    try:
        # Step 1 - recieve public key from client
        public_key = client.recv(1024)
        if not public_key:
            print(f"[ERROR] No public key received from {client.getpeername()}")
            return

        public_key = serialization.load_pem_public_key(public_key)
        with lock:
            print(f"[INFO] Received public key from {client.getpeername()}")

        try:
            # Step 2 - receive room information from client
            room_info = client.recv(1024).decode()
            if not room_info:
                print(f"[ERROR] No room information received from {client.getpeername()}")
                return

            room_info_parts = room_info.split('|')
            if len(room_info_parts) != 3:
                print(f"[ERROR] Invalid room information received from {client.getpeername()}: {room_info}")
                return
            room_id, username, password = room_info_parts
        except ConnectionResetError:
            print(f"[ERROR] Connection reset by peer before room information was received from {client.getpeername()}")
            return
        
        # Step 3 - check if the client is already in another room
        with lock:
            current_room = None
            for room, room_data in rooms.items():
                if client in room_data['clients']:
                    current_room = room
                    break

            if current_room and current_room != room_id:
                leave_room(client, current_room)\
                
        # Step 4 - add the client to the requested room or create the room if it doesn't exist
        with lock:
            if room_id not in rooms:
                rooms[room_id] = {
                    'password': password,
                    'clients': [client],
                    'public_keys': {client: public_key}
                }
                room_info = f'{room_id}|{username}|You have created the room "{room_id}" as "{username}"'
                client.send(room_info.encode())
                print(f"[INFO] Client {client.getpeername()} created room {room_id}")
            elif password == rooms[room_id]['password']:
                rooms[room_id]['clients'].append(client)
                rooms[room_id]['public_keys'][client] = public_key
                room_info = f'{room_id}|{username}|You have joined the room "{room_id}" as "{username}"'
                client.send(room_info.encode())
                print(f"[INFO] Client {client.getpeername()} joined room {room_id}")
            else:
                error_msg = f'[ERROR] Invalid password for room {room_id}'
                client.send(error_msg.encode())
                print(f"[ERROR] {error_msg}")
                return
            
        # Step 5 - broadcast the public keys to all clients in the room
        broadcast_public_keys(room_id, new_client=client)

        # Step 6 - handle messages from the client
        while True:
            try:
                # receive encrypted message from client
                encrypted_message = client.recv(1024)
                if not encrypted_message:
                    print(f"[ERROR] No message received from {client.getpeername()}")
                    break
                if encrypted_message.startswith(b'LEAVE'):
                    leave_request = encrypted_message.decode().split('|')
                    if len(leave_request) == 3:
                        _, leave_room_id, _ = leave_request
                        leave_room(client, leave_room_id)
                        print(f"[INFO] Client {client.getpeername()} left room {leave_room_id}")
                    else:
                        print(f"[ERROR] Received invalid leave request from {client.getpeername()}: {encrypted_message.decode()}")
                    break
                broadcast_message(encrypted_message, room_id, client)
            except ConnectionResetError:
                print(f"[ERROR] Connection reset by peer during message handling from {client.getpeername()}")
                break
            except Exception as e:
                print(f'[ERROR] Error handling client {client.getpeername()}: {e}')
                break

 # clean up
    except Exception as e:
        try:
            client_info = client.getpeername()
        except Exception:
            client_info = "unknown client"
        print(f'[ERROR] Error handling client {client_info}: {e}')
    finally:
        with lock:
            if client:
                try:
                    client.close()# trys to close the client connection
                except Exception as e:
                    print(f"[ERROR] Error closing client connection: {e}")
                if client in clients:
                    clients.remove(client)
                for room_id, room in rooms.items():
                    if client in room['clients']:
                        room['clients'].remove(client) # remove client from the rooms client list
                        if client in room['public_keys']:
                            del room['public_keys'][client] # remove clients public key from the room
                        if not room['clients']:
                            del rooms[room_id] # delete the room if it has no more clients
                        try:
                            print(f"[INFO] Client {client.getpeername()} has disconnected.")
                        except Exception as e:
                            print(f"[ERROR] Error getting client information: {e}")
                        break                    
# the main server loop to accept client connections
while True:
    try:
        client, addr = server_socket.accept()
        with lock:
            clients.append(client)
        print(f"[INFO] New connection from {addr}")
        threading.Thread(target=handle_client, args=(client,)).start()
    except KeyboardInterrupt:
        print("[INFO] Server is shutting down...")
        break
