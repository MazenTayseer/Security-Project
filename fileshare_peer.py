import socket
import threading
import os
from constants import Constants
import crypto_utils
import secrets
from colorama import init, Fore

init()

class FileSharePeer:
    def __init__(self, port):
        self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.port = port
        self.host = '0.0.0.0'  # Listen on all interfaces
        self.users = {}  # {username: {hashed_password, salt}}
        self.shared_files = {}  # {filename: {filepath, hash, nonce, tag, owner, shared_with}}
        self.authenticated_clients = {}  # {client_address: username}
        self.session_key = secrets.token_bytes(32)
        self.known_hosts = "5000,5001"
        os.makedirs(Constants.SHARED_FOLDER, exist_ok=True)
        os.remove(Constants.credentials_file(port)) if os.path.exists(Constants.credentials_file(port)) else None

    def start_peer(self):
        self.peer_socket.bind((self.host, self.port))
        self.peer_socket.listen(5)
        print(f"{Fore.CYAN}Peer listening on port {self.port}{Fore.RESET}")

        while True:
            client_socket, client_address = self.peer_socket.accept()
            client_thread = threading.Thread(
                target=self.handle_client_connection,
                args=(client_socket, client_address)
            )
            client_thread.start()

    def handle_client_connection(self, client_socket, client_address):
        print(f"{Fore.CYAN}Accepted connection from {client_address}{Fore.RESET}")
        try:
            while True:
                command = client_socket.recv(1024).decode().strip()
                if not command:
                    break
                
                if command == "GET_OTHER_PEERS":
                    client_socket.sendall(self.known_hosts.encode())
                    print(f"{Fore.GREEN}[+] Sent known hosts to {client_address}{Fore.RESET}")

                elif command == "REGISTER":
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
                        print(f"{Fore.GREEN}[+] Registered user: {username}{Fore.RESET}")

                elif command == "LOGIN":
                    data = client_socket.recv(1024).decode().strip()
                    username, password = data.split(":")
                    if username in self.users:
                        user = self.users[username]
                        if crypto_utils.verify_password(password, user["hashed_password"], user["salt"]):
                            self.authenticated_clients[client_address] = username
                            client_socket.sendall("SUCCESS".encode())
                            client_socket.sendall(self.session_key)
                            print(f"{Fore.GREEN}[+] User {username} logged in from {client_address}{Fore.RESET}")
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
                        client_socket.sendall("SUCCESS".encode())
                        print(f"{Fore.GREEN}[+] File '{filename}' shared with '{target_user}' by '{current_user}'{Fore.RESET}")
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
                        client_socket.sendall("SUCCESS".encode())
                        print(f"{Fore.GREEN}[+] File '{filename}' unshared with '{target_user}' by '{current_user}'{Fore.RESET}")
                    else:
                        client_socket.sendall("NOT_SHARED".encode())

                elif command == "BROADCAST_LIST":                                        
                    file_list = "\n".join(self.shared_files.keys())
                    if file_list:
                        client_socket.sendall(file_list.encode())
                    else:
                        client_socket.sendall(b"NO_FILES_FOUND")
                    print(f"{Fore.GREEN}[+] Broadcast list sent {Fore.RESET}")

                elif command in ["UPLOAD", "DOWNLOAD", "LIST", "SEARCH"]:
                    if client_address not in self.authenticated_clients:
                        client_socket.sendall("NOT_AUTHENTICATED".encode())
                        continue

                    current_user = self.authenticated_clients[client_address]

                    if command == "UPLOAD":
                        # Receive metadata: [filename|total_chunks|file_hash]
                        filename = client_socket.recv(int.from_bytes(client_socket.recv(4), 'big')).decode()
                        total_chunks = int.from_bytes(client_socket.recv(4), 'big')
                        file_hash = client_socket.recv(int.from_bytes(client_socket.recv(4), 'big'))

                        ciphertext = bytearray()
                        chunk_metadata = []
                        for chunk_index in range(total_chunks):
                            # Receive chunk: [chunk_index|nonce|tag|ciphertext]
                            received_chunk_index = int.from_bytes(client_socket.recv(4), 'big')
                            if received_chunk_index != chunk_index:
                                client_socket.sendall("INVALID_CHUNK_INDEX".encode())
                                return
                            nonce_len = int.from_bytes(client_socket.recv(4), 'big')
                            nonce = client_socket.recv(nonce_len)
                            tag_len = int.from_bytes(client_socket.recv(4), 'big')
                            tag = client_socket.recv(tag_len)
                            ciphertext_len = int.from_bytes(client_socket.recv(4), 'big')
                            chunk_ciphertext = client_socket.recv(ciphertext_len)
                            ciphertext.extend(chunk_ciphertext)
                            chunk_metadata.append({
                                "nonce": nonce,
                                "tag": tag,
                                "offset": ciphertext_len
                            })
                            print(f"{Fore.CYAN}[+] Received chunk {chunk_index + 1}/{total_chunks} for '{filename}'{Fore.RESET}")

                        filepath = os.path.join(Constants.SHARED_FOLDER, filename + ".enc")
                        with open(filepath, 'wb') as f:
                            f.write(ciphertext)

                        self.shared_files[filename] = {
                            "filepath": filepath,
                            "hash": file_hash,
                            "total_chunks": total_chunks,
                            "chunk_metadata": chunk_metadata,
                            "owner": current_user,
                            "shared_with": []
                        }
                        print(f"{Fore.GREEN}[+] Received encrypted file: {filename} from {self.authenticated_clients[client_address]}{Fore.RESET}")
                        client_socket.sendall("SUCCESS".encode())

                    elif command == "DOWNLOAD":
                        filename = client_socket.recv(int.from_bytes(client_socket.recv(4), 'big')).decode()
                        file_info = self.shared_files.get(filename, None)

                        if (file_info and os.path.exists(file_info["filepath"]) and 
                            (file_info.get("owner") == current_user or 
                             current_user in file_info.get("shared_with"))):
                            # Send metadata: [total_chunks|file_hash]
                            client_socket.sendall(b"FILE_FOUND")
                            client_socket.sendall(file_info["total_chunks"].to_bytes(4, 'big'))
                            client_socket.sendall(len(file_info["hash"]).to_bytes(4, 'big') + file_info["hash"])

                            with open(file_info["filepath"], 'rb') as f:
                                ciphertext = f.read()

                            offset = 0
                            for chunk_index in range(file_info["total_chunks"]):
                                chunk_meta = file_info["chunk_metadata"][chunk_index]
                                chunk_size = chunk_meta["offset"]
                                chunk_data = ciphertext[offset:offset + chunk_size]
                                offset += chunk_size
                                # Send chunk: [nonce|tag|ciphertext]
                                client_socket.sendall(len(chunk_meta["nonce"]).to_bytes(4, 'big') + chunk_meta["nonce"])
                                client_socket.sendall(len(chunk_meta["tag"]).to_bytes(4, 'big') + chunk_meta["tag"])
                                client_socket.sendall(len(chunk_data).to_bytes(4, 'big') + chunk_data)
                                print(f"{Fore.CYAN}[+] Sent chunk {chunk_index + 1}/{file_info['total_chunks']} for '{filename}'{Fore.RESET}")
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

                    elif command == "SEARCH":
                        keyword = client_socket.recv(int.from_bytes(client_socket.recv(4), 'big')).decode()
                        matching_files = []
                        for filename, info in self.shared_files.items():
                            if (info.get("owner") == current_user or current_user in info.get("shared_with", [])):
                                if keyword.lower() in filename.lower():
                                    owner_info = "(owner)" if info.get("owner") == current_user else f"(shared by {info.get('owner')})"
                                    matching_files.append(f"{filename} {owner_info}")

                        file_list = "\n".join(matching_files)
                        if file_list:
                            client_socket.sendall(file_list.encode())
                        else:
                            client_socket.sendall(b"NO_FILES_FOUND")

                else:
                    client_socket.sendall("UNKNOWN_COMMAND".encode())

        except Exception as e:
            print(f"{Fore.RED}Error handling client {client_address}: {e}{Fore.RESET}")
        finally:
            if client_address in self.authenticated_clients:
                del self.authenticated_clients[client_address]
            client_socket.close()
            print(f"{Fore.CYAN}Closed connection with {client_address}{Fore.RESET}")

if __name__ == "__main__":
    port = int(input("Enter port number: "))
    peer = FileSharePeer(port)
    peer.start_peer()