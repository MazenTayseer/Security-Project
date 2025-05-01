import socket
import getpass
import os
import crypto_utils

class FileShareClient:
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        self.session_key = None  # For symmetric encryption with peers
        self.is_authenticated = False

    def connect_to_peer(self, peer_address):
        try:
            self.client_socket.connect(peer_address)
            print(f"Connected to peer at {peer_address}")
            return True
        except Exception as e:
            print(f"Error connecting to peer {peer_address}: {e}")
            return False

    def register_user(self, username, password):
        hashed_password, salt = crypto_utils.hash_password(password)
        self.client_socket.sendall("REGISTER".encode())
        self.client_socket.sendall(f"{username}:{hashed_password.hex()}:{salt.hex()}".encode())
        response = self.client_socket.recv(1024).decode()
        if response == "SUCCESS":
            print(f"[+] User '{username}' registered successfully.")
            return True
        else:
            print(f"[!] Registration failed: {response}")
            return False

    def login_user(self, username, password):
        self.client_socket.sendall("LOGIN".encode())
        self.client_socket.sendall(f"{username}:{password}".encode())
        response = self.client_socket.recv(1024).decode()
        if response == "SUCCESS":
            self.username = username
            self.is_authenticated = True
            print(f"[+] User '{username}' logged in successfully.")
            return True
        else:
            print(f"[!] Login failed: {response}")
            return False

    def upload_file(self, filepath):
        if not self.is_authenticated:
            print("[!] You must be logged in to upload files.")
            return

        if not os.path.exists(filepath):
            print("[!] File does not exist.")
            return

        filename = os.path.basename(filepath)
        self.client_socket.sendall("UPLOAD".encode())
        self.client_socket.sendall(filename.encode())

        with open(filepath, 'rb') as f:
            while chunk := f.read(4096):
                self.client_socket.sendall(chunk)
        self.client_socket.sendall(b"EOF")

        print(f"[+] File '{filename}' uploaded successfully.")

    def download_file(self, filename, destination_path):
        if not self.is_authenticated:
            print("[!] You must be logged in to download files.")
            return

        self.client_socket.sendall("DOWNLOAD".encode())
        self.client_socket.sendall(filename.encode())

        full_path = os.path.join(destination_path, filename)
        os.makedirs(destination_path, exist_ok=True)

        with open(full_path, 'wb') as f:
            while True:
                chunk = self.client_socket.recv(4096)
                if chunk == b"EOF":
                    break
                elif chunk == b"FILE_NOT_FOUND":
                    print("[!] File not found on peer.")
                    return
                f.write(chunk)

        print(f"[+] File '{filename}' downloaded to '{destination_path}'")

    def search_files(self, keyword):
        # ... (Implement file search in the P2P network - broadcasting? Distributed Index? - Simplification required) ...
        pass

    def list_shared_files(self):
        if not self.is_authenticated:
            print("[!] You must be logged in to list files.")
            return

        self.client_socket.sendall("LIST".encode())
        file_list = self.client_socket.recv(4096).decode()
        print("[+] Files available on peer:")
        print(file_list if file_list else "(No files shared)")

if __name__ == "__main__":
    peer_ip = "127.0.0.1"
    peer_port = 5000

    client = FileShareClient()
    if client.connect_to_peer((peer_ip, peer_port)):
        while True:
            print("\nCommands: register, login, upload, download, list, exit")
            cmd = input("Enter command: ").strip().lower()

            if cmd == "register":
                username = input("Enter username: ")
                password = getpass.getpass("Enter password: ")
                client.register_user(username, password)

            elif cmd == "login":
                username = input("Enter username: ")
                password = getpass.getpass("Enter password: ")
                client.login_user(username, password)

            elif cmd == "upload":
                path = input("Enter full path of file to upload: ")
                client.upload_file(path)

            elif cmd == "download":
                filename = input("Enter filename to download: ")
                dest = "downloads"
                client.download_file(filename, dest)

            elif cmd == "list":
                client.list_shared_files()

            elif cmd == "exit":
                print("[+] Exiting.")
                client.client_socket.close()
                break

            else:
                print("[!] Unknown command.")