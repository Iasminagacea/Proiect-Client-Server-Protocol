# Client-Server Protocol Project

## Overview

This project implements a Unix socket-based client-server communication protocol. The server manages user authentication and provides system information, while the client connects to the server and sends commands to retrieve data.

## Features

- **User Authentication**: Login using valid usernames stored in `users.txt`
- **Logged Users List**: Retrieve all currently logged-in users on the system
- **Process Information**: Query detailed information about processes by their PID
- **Unix Socket Communication**: Uses Unix domain sockets for efficient local IPC
- **Message Protocol**: Implements a length-prefixed message protocol for reliable data transmission

## Commands

- `login <username>` - Authenticate with a username
- `get-logged-users` - Display all logged-in users
- `get-proc-info <pid>` - Show process information for a given PID
- `logout` - Log out from the server
- `quit` - Disconnect and exit

## Requirements

- Linux/Unix-based system
- C compiler (gcc)
- Standard POSIX libraries

## Usage

1. Start the server: `./server`
2. In another terminal, run the client: `./client`
3. Use the available commands to interact with the server