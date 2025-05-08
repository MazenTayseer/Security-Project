import socket
import getpass
import os
import crypto_utils

class FileShareClient:
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        self.session_key = None
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
        else:
            print(f"[!] Registration failed: {response}")

    def login_user(self, username, password):
        self.client_socket.sendall("LOGIN".encode())
        self.client_socket.sendall(f"{username}:{password}".encode())
        response = self.client_socket.recv(1024).decode()
        if response == "SUCCESS":
            self.username = username
            self.is_authenticated = True
            self.session_key = self.client_socket.recv(32)
            print(f"[+] User '{username}' logged in successfully.")
        else:
            print(f"[!] Login failed: {response}")

    def share_file(self, filename, target_user):
        if not self.is_authenticated:
            print("[!] You must be logged in to share files.")
            return False
            
        self.client_socket.sendall("SHARE_FILE".encode())
        self.client_socket.sendall(f"{filename}:{target_user}".encode())
        response = self.client_socket.recv(1024).decode()
        
        if response == "SUCCESS":
            print(f"[+] File '{filename}' shared with '{target_user}' successfully.")
            return True
        else:
            print(f"[!] Failed to share file: {response}")
            return False
            
    def unshare_file(self, filename, target_user):
        if not self.is_authenticated:
            print("[!] You must be logged in to modify file permissions.")
            return False
            
        self.client_socket.sendall("UNSHARE_FILE".encode())
        self.client_socket.sendall(f"{filename}:{target_user}".encode())
        response = self.client_socket.recv(1024).decode()
        
        if response == "SUCCESS":
            print(f"[+] Access to '{filename}' revoked from '{target_user}' successfully.")
            return True
        else:
            print(f"[!] Failed to revoke access: {response}")
            return False

    def upload_file(self, filepath):
        if not self.is_authenticated:
            print("[!] You must be logged in to upload files.")
            return

        if not os.path.exists(filepath):
            print("[!] File does not exist.")
            return

        filename = os.path.basename(filepath)
        with open(filepath, 'rb') as f:
            plaintext = f.read()

        file_hash = crypto_utils.compute_file_hash(plaintext)
        ciphertext, nonce, tag = crypto_utils.encrypt_file(plaintext, self.session_key)

        self.client_socket.sendall("UPLOAD".encode())
        # Send metadata: [filename|hash|nonce|tag|ciphertext]
        filename_bytes = filename.encode()
        data = (len(filename_bytes).to_bytes(4, 'big') + filename_bytes +
                len(file_hash).to_bytes(4, 'big') + file_hash +
                len(nonce).to_bytes(4, 'big') + nonce +
                len(tag).to_bytes(4, 'big') + tag +
                len(ciphertext).to_bytes(4, 'big') + ciphertext)
        self.client_socket.sendall(data)
        
        response = self.client_socket.recv(1024).decode()
        if response == "SUCCESS":
            print(f"[+] File '{filename}' uploaded successfully (encrypted).")
        else:
            print(f"[!] Upload failed: {response}")

    def download_file(self, filename, destination_path):
        if not self.is_authenticated:
            print("[!] You must be logged in to download files.")
            return

        self.client_socket.sendall("DOWNLOAD".encode())
        filename_bytes = filename.encode()
        self.client_socket.sendall(len(filename_bytes).to_bytes(4, 'big') + filename_bytes)

        initial_response = self.client_socket.recv(1024).decode()
        if initial_response == "FILE_NOT_FOUND":
            print("[!] File not found on peer.")
            return

        # Receive metadata: [hash|nonce|tag|ciphertext]
        hash_len = int.from_bytes(self.client_socket.recv(4), 'big')
        file_hash = self.client_socket.recv(hash_len)
        nonce_len = int.from_bytes(self.client_socket.recv(4), 'big')
        nonce = self.client_socket.recv(nonce_len)
        tag_len = int.from_bytes(self.client_socket.recv(4), 'big')
        tag = self.client_socket.recv(tag_len)
        ciphertext_len = int.from_bytes(self.client_socket.recv(4), 'big')
        ciphertext = self.client_socket.recv(ciphertext_len)

        try:
            plaintext = crypto_utils.decrypt_file(ciphertext, self.session_key, nonce, tag)
            if not crypto_utils.verify_file_hash(plaintext, file_hash):
                print("[!] Integrity check failed: File hash does not match.")
                return

            full_destination_path = os.path.join(destination_path, self.username)
            os.makedirs(full_destination_path, exist_ok=True)
            full_path = os.path.join(full_destination_path, filename)
            with open(full_path, 'wb') as f:
                f.write(plaintext)

            print(f"[+] File '{filename}' downloaded and decrypted to '{full_destination_path}'")
        except Exception:
            print("[!] An error occured.")
            return

    def search_files(self, keyword):
        # ... (Implement file search in the P2P network - broadcasting? Distributed Index? - Simplification required) ...
        pass

    def list_users(self):
        if not self.is_authenticated:
            print("[!] You must be logged in to list users.")
            return
            
        self.client_socket.sendall("LIST_USERS".encode())
        users = self.client_socket.recv(1024).decode()

        if users == "NO_USERS_FOUND":
            print("[!] No users.")
        else:
            print("[+] Current Users:")
            print(users)

    def list_shared_files(self):
        if not self.is_authenticated:
            print("[!] You must be logged in to list files.")
            return

        self.client_socket.sendall("LIST".encode())
        file_list = self.client_socket.recv(4096).decode()

        if file_list == "NO_FILES_FOUND":
            print("[!] No files available to you.")
        else:
            print("[+] Files available to you:")
            print(file_list)

if __name__ == "__main__":
    peer_ip = "127.0.0.1"
    peer_port = 5000

    client = FileShareClient()
    if client.connect_to_peer((peer_ip, peer_port)):
        while True:
            print("\nCommands: register, login, upload, download, list, list-users, share, unshare, exit")
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
                
            elif cmd == "list-users":
                client.list_users()
                
            elif cmd == "share":
                filename = input("Enter filename to share: ")
                user_choice = input("Enter username to share with: ")
                client.share_file(filename, user_choice)
                
            elif cmd == "unshare":
                filename = input("Enter filename to unshare: ")
                user_choice = input("Enter username to revoke access from: ")
                client.unshare_file(filename, user_choice)

            elif cmd == "exit":
                print("[+] Exiting.")
                client.client_socket.close()
                break

            else:
                print("[!] Unknown command.")