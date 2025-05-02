import socket
import threading
import os
import crypto_utils
import secrets

class FileSharePeer:
    def __init__(self, port):
        self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.port = port
        self.host = '0.0.0.0'  # Listen on all interfaces
        self.users = {}  # {username: {hashed_password, salt}}
        self.shared_files = {}  # {filename: {filepath, hash, nonce, tag}}
        self.authenticated_clients = {}  # {client_address: username}
        self.session_key = secrets.token_bytes(32)
        os.makedirs("shared", exist_ok=True)

    def start_peer(self):
        self.peer_socket.bind((self.host, self.port))
        self.peer_socket.listen(5)
        print(f"Peer listening on port {self.port}")

        while True:
            client_socket, client_address = self.peer_socket.accept()
            client_thread = threading.Thread(
                target=self.handle_client_connection,
                args=(client_socket, client_address)
            )
            client_thread.start()

    def handle_client_connection(self, client_socket, client_address):
        print(f"Accepted connection from {client_address}")
        try:
            while True:
                command = client_socket.recv(1024).decode().strip()
                if not command:
                    break

                if command == "REGISTER":
                    data = client_socket.recv(1024).decode().strip()
                    username, hashed_password_hex, salt_hex = data.split(":")
                    hashed_password = bytes.fromhex(hashed_password_hex)
                    salt = bytes.fromhex(salt_hex)
                    if username in self.users:
                        client_socket.sendall("USER_EXISTS".encode())
                    else:
                        self.users[username] = {
                            "hashed_password": hashed_password,
                            "salt": salt
                        }
                        client_socket.sendall("SUCCESS".encode())
                        print(f"[+] Registered user: {username}")

                elif command == "LOGIN":
                    data = client_socket.recv(1024).decode().strip()
                    username, password = data.split(":")
                    if username in self.users:
                        user = self.users[username]
                        if crypto_utils.verify_password(password, user["hashed_password"], user["salt"]):
                            self.authenticated_clients[client_address] = username
                            client_socket.sendall("SUCCESS".encode())
                            client_socket.sendall(self.session_key)
                            print(f"[+] User {username} logged in from {client_address}")
                        else:
                            client_socket.sendall("INVALID_CREDENTIALS".encode())
                    else:
                        client_socket.sendall("USER_NOT_FOUND".encode())

                elif command in ["UPLOAD", "DOWNLOAD", "LIST"]:
                    if client_address not in self.authenticated_clients:
                        client_socket.sendall("NOT_AUTHENTICATED".encode())
                        continue

                    if command == "UPLOAD":
                        # Receive metadata: [filename|hash|nonce|tag|ciphertext]
                        filename = client_socket.recv(int.from_bytes(client_socket.recv(4), 'big')).decode()
                        file_hash = client_socket.recv(int.from_bytes(client_socket.recv(4), 'big'))
                        nonce = client_socket.recv(int.from_bytes(client_socket.recv(4), 'big'))
                        tag = client_socket.recv(int.from_bytes(client_socket.recv(4), 'big'))
                        ciphertext = client_socket.recv(int.from_bytes(client_socket.recv(4), 'big'))

                        filepath = os.path.join("shared", filename + ".enc")
                        with open(filepath, 'wb') as f:
                            f.write(ciphertext)

                        # Store metadata
                        self.shared_files[filename] = {
                            "filepath": filepath,
                            "hash": file_hash,
                            "nonce": nonce,
                            "tag": tag
                        }
                        print(f"[+] Received encrypted file: {filename} from {self.authenticated_clients[client_address]}")

                    elif command == "DOWNLOAD":
                        filename = client_socket.recv(int.from_bytes(client_socket.recv(4), 'big')).decode()
                        file_info = self.shared_files.get(filename, None)

                        if file_info and os.path.exists(file_info["filepath"]):
                            # Send metadata: [hash|nonce|tag|ciphertext]
                            client_socket.sendall(b"FILE_FOUND")
                            client_socket.sendall(len(file_info["hash"]).to_bytes(4, 'big') + file_info["hash"])
                            client_socket.sendall(len(file_info["nonce"]).to_bytes(4, 'big') + file_info["nonce"])
                            client_socket.sendall(len(file_info["tag"]).to_bytes(4, 'big') + file_info["tag"])
                            with open(file_info["filepath"], 'rb') as f:
                                ciphertext = f.read()
                            client_socket.sendall(len(ciphertext).to_bytes(4, 'big') + ciphertext)
                            print(f"[+] Sent encrypted file: {filename} to {self.authenticated_clients[client_address]}")
                        else:
                            client_socket.sendall(b"FILE_NOT_FOUND")

                    elif command == "LIST":
                        file_list = "\n".join(self.shared_files.keys())
                        if file_list:
                            client_socket.sendall(file_list.encode())
                        else:
                            client_socket.sendall(b"NO_FILES_FOUND")

                else:
                    client_socket.sendall("UNKNOWN_COMMAND".encode())

        except Exception as e:
            print(f"Error handling client {client_address}: {e}")
        finally:
            if client_address in self.authenticated_clients:
                del self.authenticated_clients[client_address]
            client_socket.close()
            print(f"Closed connection with {client_address}")

if __name__ == "__main__":
    port = 5000
    peer = FileSharePeer(port)
    peer.start_peer()