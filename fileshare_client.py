import socket
import getpass
import os
import json
from constants import Constants
import crypto_utils
import math
import re

class FileShareClient:
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        self.session_key = None
        self.is_authenticated = False
        self.credentials_file = Constants.CREDENTIALS_ENC
        self.chunk_size = 1024 * 1024

    def __password_check(self, password):
        if len(password) < 8:
            return "Password must be at least 8 characters long."
        if not re.search(r"[A-Z]", password):
            return "Password must contain at least one uppercase letter."
        if not re.search(r"[a-z]", password):
            return "Password must contain at least one lowercase letter."
        if not re.search(r"[0-9]", password):
            return "Password must contain at least one digit."
        return None

    def connect_to_peer(self, peer_address):
        try:
            self.client_socket.connect(peer_address)
            print(f"Connected to peer at {peer_address}")
            return True
        except Exception as e:
            print(f"Error connecting to peer {peer_address}: {e}")
            return False
        
    def save_credentials(self, username, password):
        try:
            key = crypto_utils.derive_key_from_password(password, username.encode())
            credentials = {"username": username, "password": password}
            credentials_json = json.dumps(credentials).encode('utf-8')
            ciphertext, nonce, tag = crypto_utils.aes_encryption(credentials_json, key)
            with open(self.credentials_file, 'wb') as f:
                f.write(len(username.encode()).to_bytes(4, 'big') + username.encode() +
                        len(nonce).to_bytes(4, 'big') + nonce +
                        len(tag).to_bytes(4, 'big') + tag +
                        ciphertext)
            print(f"[+] Credentials saved to {self.credentials_file}")
        except Exception as e:
            print(f"[!] Error saving credentials: {e}")

    def load_credentials(self):
        try:
            if not os.path.exists(self.credentials_file):
                print("[!] No saved credentials found.")
                return None, None

            with open(self.credentials_file, 'rb') as f:
                data = f.read()
            username_len = int.from_bytes(data[:4], 'big')
            username = data[4:4+username_len].decode()
            nonce_len = int.from_bytes(data[4+username_len:8+username_len], 'big')
            nonce = data[8+username_len:8+username_len+nonce_len]
            tag_len = int.from_bytes(data[8+username_len+nonce_len:12+username_len+nonce_len], 'big')
            tag = data[12+username_len+nonce_len:12+username_len+nonce_len+tag_len]
            ciphertext = data[12+username_len+nonce_len+tag_len:]

            password = getpass.getpass(f"Enter password for user '{username}': ")
                
            key = crypto_utils.derive_key_from_password(password, username.encode())
            try:
                credentials_json = crypto_utils.decrypt_file(ciphertext, key, nonce, tag)
                credentials = json.loads(credentials_json.decode('utf-8'))
                print(f"[+] Loaded credentials for user: {username}")
                return username, credentials["password"]
            except Exception:
                print("[!] Decryption failed: Invalid password.")
                return None, None
        except Exception as e:
            print(f"[!] Error loading credentials: {e}")
            return None, None

    def delete_credentials(self):
        try:
            if os.path.exists(self.credentials_file):
                os.remove(self.credentials_file)
                print(f"[+] Credentials file {self.credentials_file} deleted.")
            else:
                print("[!] No credentials file to delete.")
        except Exception as e:
            print(f"[!] Error deleting credentials: {e}")

    def register_user(self, username, password):
        if len(username) < 4:
            print("[!] Registration failed: Username must be at least 4 characters.")
            return
        password_error = self.__password_check(password)
        while password_error:
            print(f"[!] Registration failed: {password_error}")
            password = getpass.getpass("Enter password: ")
            password_error = self.__password_check(password)
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
            return True
        else:
            print(f"[!] Login failed: {response}")
            return False

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
        file_size = os.path.getsize(filepath)
        total_chunks = math.ceil(file_size / self.chunk_size)

        with open(filepath, 'rb') as f:
            plaintext = f.read()
        file_hash = crypto_utils.compute_file_hash(plaintext)

        self.client_socket.sendall("UPLOAD".encode())
        # Send metadata: [filename|total_chunks|file_hash]
        filename_bytes = filename.encode()
        metadata = (len(filename_bytes).to_bytes(4, 'big') + filename_bytes +
                    total_chunks.to_bytes(4, 'big') +
                    len(file_hash).to_bytes(4, 'big') + file_hash)
        self.client_socket.sendall(metadata)

        with open(filepath, 'rb') as f:
            for chunk_index in range(total_chunks):
                chunk_data = f.read(self.chunk_size)
                if not chunk_data:
                    break
                ciphertext, nonce, tag = crypto_utils.aes_encryption(chunk_data, self.session_key)
                # Send chunk: [chunk_index|nonce|tag|ciphertext]
                chunk_metadata = (chunk_index.to_bytes(4, 'big') +
                                 len(nonce).to_bytes(4, 'big') + nonce +
                                 len(tag).to_bytes(4, 'big') + tag +
                                 len(ciphertext).to_bytes(4, 'big') + ciphertext)
                self.client_socket.sendall(chunk_metadata)
                print(f"[+] Sent chunk {chunk_index + 1}/{total_chunks} for '{filename}'")

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

        # Receive metadata: [total_chunks|file_hash]
        total_chunks = int.from_bytes(self.client_socket.recv(4), 'big')
        hash_len = int.from_bytes(self.client_socket.recv(4), 'big')
        file_hash = self.client_socket.recv(hash_len)

        plaintext = bytearray()
        for chunk_index in range(total_chunks):
            # Receive chunk: [nonce|tag|ciphertext]
            try:
                nonce_len = int.from_bytes(self.client_socket.recv(4), 'big')
                nonce = self.client_socket.recv(nonce_len)
                tag_len = int.from_bytes(self.client_socket.recv(4), 'big')
                tag = self.client_socket.recv(tag_len)
                ciphertext_len = int.from_bytes(self.client_socket.recv(4), 'big')
                ciphertext = self.client_socket.recv(ciphertext_len)

                try:
                    chunk_data = crypto_utils.decrypt_file(ciphertext, self.session_key, nonce, tag)
                    plaintext.extend(chunk_data)
                    print(f"[+] Received chunk {chunk_index + 1}/{total_chunks} for '{filename}'")
                except Exception as e:
                    print(f"[!] Error decrypting chunk {chunk_index + 1}: {e}")
                    return
            except Exception as e:
                print(f"[!] Error receiving chunk {chunk_index + 1} metadata: {e}")
                return

        # Verify file integrity
        if not crypto_utils.verify_file_hash(plaintext, file_hash):
            print("[!] Integrity check failed: File hash does not match.")
            return

        full_destination_path = os.path.join(destination_path, self.username)
        os.makedirs(full_destination_path, exist_ok=True)
        full_path = os.path.join(full_destination_path, filename)
        with open(full_path, 'wb') as f:
            f.write(plaintext)

        print(f"[+] File '{filename}' downloaded and decrypted to '{full_destination_path}'")

    def search_files(self, keyword):
        if not self.is_authenticated:
            print("[!] You must be logged in to search files.")
            return

        self.client_socket.sendall("SEARCH".encode())
        keyword_bytes = keyword.encode()
        self.client_socket.sendall(len(keyword_bytes).to_bytes(4, 'big') + keyword_bytes)

        response = self.client_socket.recv(4096).decode()
        if response == "NO_FILES_FOUND":
            print(f"[!] No files found matching '{keyword}'.")
        else:
            print(f"[+] Files matching '{keyword}':")
            print(response)

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

    def logout(self):
        if not self.is_authenticated:
            print("[!] You are not logged in.")
            return

        self.is_authenticated = False
        self.username = None
        self.session_key = None
        self.client_socket.close()
        print(f"[+] Logged out user '{self.username}'.")

if __name__ == "__main__":
    peer_ip = "127.0.0.1"
    peer_port = 5000

    client = FileShareClient()
    if client.connect_to_peer((peer_ip, peer_port)):
        if os.path.exists(client.credentials_file):
            print("[+] Found saved credentials.")
            auto_login = input("Attempt auto-login? (y/n): ").strip().lower()
            if auto_login == 'y':
                username, password = client.load_credentials()
                if username and password:
                    client.login_user(username, password)
            else:
                print("[+] Skipping auto-login.")

        while True:
            print("\nCommands: register, login, upload, download, list, list-users, share, unshare, delete-credentials, logout, search, exit")
            cmd = input("Enter command: ").strip().lower()

            if cmd == "register":
                username = input("Enter username: ")
                password = getpass.getpass("Enter password: ")
                client.register_user(username, password)

            elif cmd == "login":
                username = input("Enter username: ")
                password = getpass.getpass("Enter password: ")
                if client.login_user(username, password):
                    save = input("Save credentials for auto-login? (y/n): ").strip().lower()
                    if save == 'y':
                        client.save_credentials(username, password)

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

            elif cmd == "search":
                keyword = input("Enter keyword to search for: ")
                client.search_files(keyword)

            elif cmd == "exit":
                print("[+] Exiting.")
                client.client_socket.close()
                break

            elif cmd == "delete-credentials":
                client.delete_credentials()

            elif cmd == "logout":
                client.logout()

            else:
                print("[!] Unknown command.")