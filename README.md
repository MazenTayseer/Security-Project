# File Sharing P2P

## Steps to run project

- clone the repository
  ```
  git clone https://github.com/MazenTayseer/Security-Project.git
  ```
- In the folder, create a venv and activate it
  ```
  python -m venv .venv
  source .venv/Scripts/activate
  ```
- install the requirements
  ```
  pip install -r requirements.txt
  ```
- to start the peer
  ```
  python fileshare_peer.py
  ```
- to start a client
  ```
  python fileshare_client.py
  ```

## Features

### File Sharing with Access Control

- Users can register and login with secure password hashing
- Files are encrypted before transmission and storage
- Access control allows sharing files with specific users
- File owners can manage permissions:
  - Share files with specific users
  - Revoke access to previously shared files
  - View ownership information for all accessible files

### Commands

- `register` - Create a new user account
- `login` - Authenticate with username and password
- `upload` - Upload and encrypt a file to the peer
- `download` - Download and decrypt a file (if you have access)
- `list` - View all files you own or have been shared with you
- `list-users` - View all registered users available to share with
- `share` - Share one of your files with another user
- `unshare` - Revoke access to one of your files from a user
- `exit` - Close the connection

## TODO

- passphrase in server stored