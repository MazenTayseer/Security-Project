import socket
import threading
import os
from constants import Constants
import crypto_utils
import secrets
import json

class FileSharePeer:
    def __init__(self, port):
        self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.port = port
        self.host = '0.0.0.0'  # Listen on all interfaces
        self.users = {}  # {username: {hashed_password, salt}}
        self.shared_files = {}  # {filename: {filepath, hash, nonce, tag, owner, shared_with}}
        self.authenticated_clients = {}  # {client_address: username}
        self.session_key = secrets.token_bytes(32)
        os.makedirs(Constants.SHARED_FOLDER, exist_ok=True)
        os.makedirs(Constants.DB_FOLDER, exist_ok=True)

        self.__load_state()

    def __load_state(self):
        user_file = f"{Constants.DB_FOLDER}/users.json"
        if os.path.getsize(user_file) > 0:
            with open(user_file, 'r') as f:
                user_data = json.load(f)
                for username, data in user_data.items():
                    self.users[username] = {
                        "hashed_password": bytes.fromhex(data["hashed_password"]),
                        "salt": bytes.fromhex(data["salt"])
                    }

        file_path = f"{Constants.DB_FOLDER}/files.json"
        if os.path.getsize(file_path):
            with open(file_path, 'r') as f:
                file_data = json.load(f)
                for filename, data in file_data.items():
                    if os.path.exists(data["filepath"]):
                        self.shared_files[filename] = {
                            "filepath": data["filepath"],
                            "hash": bytes.fromhex(data["hash"]) if isinstance(data["hash"], str) else data["hash"],
                            "nonce": bytes.fromhex(data["nonce"]) if isinstance(data["nonce"], str) else data["nonce"],
                            "tag": bytes.fromhex(data["tag"]) if isinstance(data["tag"], str) else data["tag"],
                            "owner": data["owner"],
                            "shared_with": data.get("shared_with", [])
                        }

    def __save_state(self):
        with open(f"{Constants.DB_FOLDER}/users.json", 'w') as f:
            # Convert bytes to hex strings for JSON serialization
            serializable_users = {}
            for username, data in self.users.items():
                serializable_users[username] = {
                    "hashed_password": data["hashed_password"].hex(),
                    "salt": data["salt"].hex()
                }
            json.dump(serializable_users, f)
        
        with open(f"{Constants.DB_FOLDER}/files.json", 'w') as f:
            # Convert bytes to hex strings for JSON serialization
            serializable_files = {}
            for filename, data in self.shared_files.items():
                serializable_files[filename] = {
                    "filepath": data["filepath"],
                    "hash": data["hash"].hex() if isinstance(data["hash"], bytes) else data["hash"],
                    "nonce": data["nonce"].hex() if isinstance(data["nonce"], bytes) else data["nonce"],
                    "tag": data["tag"].hex() if isinstance(data["tag"], bytes) else data["tag"],
                    "owner": data["owner"],
                    "shared_with": data.get("shared_with", [])
                }
            json.dump(serializable_files, f)

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
                        self.__save_state()
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

                elif command == "LIST_USERS":
                    if client_address not in self.authenticated_clients:
                        client_socket.sendall("NOT_AUTHENTICATED".encode())
                        continue
                    
                    if self.users.keys():
                        user_list = "\n".join(self.users.keys())
                        client_socket.sendall(user_list.encode())
                    else:
                        client_socket.sendall(b"NO_USERS_FOUND")

                elif command == "SHARE_FILE":
                    if client_address not in self.authenticated_clients:
                        client_socket.sendall("NOT_AUTHENTICATED".encode())
                        continue
                    
                    current_user = self.authenticated_clients[client_address]
                    data = client_socket.recv(1024).decode().strip()
                    filename, target_user = data.split(":")
                    
                    if filename not in self.shared_files:
                        client_socket.sendall("FILE_NOT_FOUND".encode())
                        continue
                        
                    if target_user not in self.users:
                        client_socket.sendall("USER_NOT_FOUND".encode())
                        continue
                        
                    file_info = self.shared_files[filename]
                    if file_info.get("owner") != current_user:
                        client_socket.sendall("NOT_OWNER".encode())
                        continue
                        
                    if target_user not in file_info["shared_with"]:
                        file_info["shared_with"].append(target_user)
                        self.__save_state()
                        client_socket.sendall("SUCCESS".encode())
                        print(f"[+] File '{filename}' shared with '{target_user}' by '{current_user}'")
                    else:
                        client_socket.sendall("ALREADY_SHARED".encode())

                elif command == "UNSHARE_FILE":
                    if client_address not in self.authenticated_clients:
                        client_socket.sendall("NOT_AUTHENTICATED".encode())
                        continue
                    
                    current_user = self.authenticated_clients[client_address]
                    data = client_socket.recv(1024).decode().strip()
                    filename, target_user = data.split(":")
                    
                    if filename not in self.shared_files:
                        client_socket.sendall("FILE_NOT_FOUND".encode())
                        continue
                        
                    file_info = self.shared_files[filename]
                    if file_info.get("owner") != current_user:
                        client_socket.sendall("NOT_OWNER".encode())
                        continue
                        
                    if "shared_with" in file_info and target_user in file_info["shared_with"]:
                        file_info["shared_with"].remove(target_user)
                        self.__save_state()
                        client_socket.sendall("SUCCESS".encode())
                        print(f"[+] File '{filename}' unshared with '{target_user}' by '{current_user}'")
                    else:
                        client_socket.sendall("NOT_SHARED".encode())

                elif command in ["UPLOAD", "DOWNLOAD", "LIST"]:
                    if client_address not in self.authenticated_clients:
                        client_socket.sendall("NOT_AUTHENTICATED".encode())
                        continue

                    current_user = self.authenticated_clients[client_address]

                    if command == "UPLOAD":
                        # Receive metadata: [filename|hash|nonce|tag|ciphertext]
                        filename = client_socket.recv(int.from_bytes(client_socket.recv(4), 'big')).decode()
                        file_hash = client_socket.recv(int.from_bytes(client_socket.recv(4), 'big'))
                        nonce = client_socket.recv(int.from_bytes(client_socket.recv(4), 'big'))
                        tag = client_socket.recv(int.from_bytes(client_socket.recv(4), 'big'))
                        ciphertext = client_socket.recv(int.from_bytes(client_socket.recv(4), 'big'))

                        filepath = os.path.join(Constants.SHARED_FOLDER, filename + ".enc")
                        with open(filepath, 'wb') as f:
                            f.write(ciphertext)

                        # Store metadata with ownership information
                        self.shared_files[filename] = {
                            "filepath": filepath,
                            "hash": file_hash,
                            "nonce": nonce,
                            "tag": tag,
                            "owner": current_user,
                            "shared_with": []
                        }
                        self.__save_state()
                        print(f"[+] Received encrypted file: {filename} from {self.authenticated_clients[client_address]}")
                        client_socket.sendall("SUCCESS".encode())

                    elif command == "DOWNLOAD":
                        filename = client_socket.recv(int.from_bytes(client_socket.recv(4), 'big')).decode()
                        file_info = self.shared_files.get(filename, None)

                        if (file_info and os.path.exists(file_info["filepath"]) and 
                            (file_info.get("owner") == current_user or 
                             current_user in file_info.get("shared_with"))):
                      
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
                        accessible_files = []
                        for filename, info in self.shared_files.items():
                            if (info.get("owner") == current_user or 
                                current_user in info.get("shared_with", [])):
                                
                                owner_info = "(owner)" if info.get("owner") == current_user else f"(shared by {info.get('owner')})"
                                accessible_files.append(f"{filename} {owner_info}")
                                
                        file_list = "\n".join(accessible_files)
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