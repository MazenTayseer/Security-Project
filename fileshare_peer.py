import socket 
import threading 
import os 

# ... (Data structures for user info, shared files, peer lists etc.) ...

class FileSharePeer: 
    def __init__(self, port): 
        self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        self.port = port 
        self.host = '0.0.0.0' # Listen on all interfaces 
        self.users = {} # {username: {hashed_password, salt, ...}} - In-memory for simplicity, consider file-based storage for persistence 
        self.shared_files = {} # {file_id: {filepath, owner_username, ...}} - Track files shared by this peer 
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
                # ... (Receive commands from client - register, login, upload, download, search, etc. - define a simple protocol) ... 
                command = client_socket.recv(1024).decode() # Example - define command structure 

                if command == "REGISTER": 
                    # ... (Handle user registration - receive username, hashed password+salt, store user info) ... 
                    pass 
                elif command == "LOGIN": 
                    # ... (Handle login - receive username, password, verify password against stored hash, create session - simplified) ... 
                    pass 
                elif command == "UPLOAD":
                    filename = client_socket.recv(1024).decode().strip()
                    filepath = os.path.join("shared", filename)

                    
                    with open(filepath, 'wb') as f:
                        while True:
                            chunk = client_socket.recv(4096)
                            if chunk == b"EOF":
                                break
                            f.write(chunk)

                    self.shared_files[filename] = filepath
                    print(f"[+] Received file: {filename}")
                elif command == "DOWNLOAD": 
                    client_socket.send(b"1")
                    filename = client_socket.recv(1024).decode().strip()
                    filepath = self.shared_files.get(filename)

                    if filepath and os.path.exists(filepath):
                        with open(filepath, 'rb') as f:
                            while chunk := f.read(4096):
                                client_socket.send(chunk)
                        client_socket.send(b"EOF")
                        print(f"[+] Sent file: {filename}")
                    else:
                        client_socket.send(b"FILE_NOT_FOUND")
                elif command == "SEARCH": 
                    # ... (Receive search keyword, search local shared files, respond with file list - for simplified P2P search) ... 
                    pass
                elif command == "LIST":
                    file_list = "\n".join(self.shared_files.keys())
                    client_socket.send(file_list.encode())
                # ... (Handle other commands) ... 

        except Exception as e: 
            print(f"Error handling client {client_address}: {e}") 
        finally: 
            client_socket.close() 

    # ... (Methods for user registration, login, file upload, download, search, P2P network functions) ...

# ... (Peer program entry point - start the peer node) ...
if __name__ == "__main__":
    port = 5000
    peer = FileSharePeer(port)
    peer.start_peer()
