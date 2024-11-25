
# TwMailerPro

## Overview
TW-Mailer Pro is an enhanced version of the TW-Mailer project, designed for efficient and secure email communication. This version introduces a concurrent server model that uses fork() for handling multiple client connections simultaneously, ensuring scalability and responsiveness. It also features LDAP-based authentication for managing user credentials securely, along with session management and advanced email handling. The new version enforces stricter security measures, such as login attempt limits and IP blacklisting, while retaining the original command-line client-server architecture for simplicity and usability.

## Technologies
The TW-Mailer Pro project is implemented in C++, leveraging modern programming paradigms for robust and efficient execution. Key technologies and tools include:

- **Programming Language**: C++ for client and server implementation.
- **Libraries**:
  - **Socket Programming**: `sys/socket.h`, `arpa/inet.h`, etc.
  - **LDAP**: OpenLDAP API for authentication (`ldap.h`).
  - **Filesystem**: C++17 `<filesystem>` for directory management.
- **Concurrency**: `fork()` for handling multiple clients simultaneously.
- **Persistent Storage**: Email messages and blacklist data are stored in user-specific directories.

### Core Functionalities

#### Login with LDAP Authentication
- Validates credentials against an LDAP server.
- Limits failed login attempts to 3 per user/IP.
- Blacklists IPs for 1 minute after 3 failed attempts, with persistence.

#### Session-Based Command Authorization
- Only authenticated users can access commands such as `SEND`, `LIST`, `READ`, and `DEL`.
- User and sender are automatically set based on session information.

#### Concurrent Server Handling
- The server supports multiple simultaneous client connections using `fork()`.

#### Enhanced Message Management
- Messages are saved in user-specific directories.
- Subject length is limited to 80 characters, and message content supports multi-line input.

#### Persistent Blacklist
- Ensures security by persisting blacklisted IPs across server restarts.

## Features
- **Login**: Authenticate users by verifying credentials against an LDAP server.
- **Send Messages**: Send messages to other users and save them in the recipient's directory.
- **List Messages**: View all messages in your own inbox (directory).
- **Read Messages**: Read specific messages in your own directory.
- **Delete Messages**: Delete specific messages from your own directory.

## User Input

```SEND```: Send a message to a specified recipient and save it in their directory.
   - **Format**:
     ```
     receiver: <recipient_username>
     subject: <subject_of_the_message>
     message: <your_message_content>
     ```
     
```LIST```: List all messages in your own inbox (directory).

```READ```: Read specific messages in your own directory.
   - **Format**:
     ```
     message-number: <number>
     ```

```DEL```: Delete a specific message from your own directory.
   - **Format**:
     ```
     message-number: <number>
     ```

```QUIT```: Disconnect from the server.

## Server Response
- **OK**: The message was successfully sent.
- **ERR**: The operation failed.

## Installation
To set up TwMailerPro, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/moaiadmhanna/TwMailerPro.git
   ```

2. Navigate to the project directory:
   ```bash
   cd TwMailerPro
   ```

3. Build the project using:
   ```bash
   make all
   ```

## Running the Project

### Server Side
To start the TwMailerPro server, run the following command:
```bash
./twmailer-pro-server.out <port> <mail_spool_directory>
```
- `<port>`: Specify the port number for the server.
- `<mail_spool_directory>`: Specify the directory where messages will be stored.

### Client Side
To start the TwMailerPro client, run the following command:
```bash
./twmailer-pro-client.out <ip> <port>
```
- `<ip>`: Specify the server's IP address.
- `<port>`: Specify the port number on which the server is running.
