import socket
from urllib.parse import quote

# -------------------------------------------------
# Server configuration
# -------------------------------------------------

HOST = "127.0.0.1"
PORT = 5000

# -------------------------------------------------
# Choose HTTP method
# -------------------------------------------------

method = input("Enter request method (GET/POST): ").upper()

# -------------------------------------------------
# Get username
# -------------------------------------------------

username = input("Enter username: ")

# -------------------------------------------------
# URL encode username
# -------------------------------------------------

encoded_username = quote(username)

# -------------------------------------------------
# Create HTTP request
# -------------------------------------------------

if method == "GET":

    request = (
        f"GET /login?username={encoded_username} HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Connection: close\r\n"
        "\r\n"
    )

elif method == "POST":

    body = f"username={encoded_username}"

    request = (
        "POST /login HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body.encode('utf-8'))}\r\n"
        "Connection: close\r\n"
        "\r\n"
        f"{body}"
    )

else:

    print("Invalid request method!")
    exit()

# -------------------------------------------------
# Create TCP socket
# -------------------------------------------------

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:

    # -------------------------------------------------
    # Connect to server
    # -------------------------------------------------

    client.connect((HOST, PORT))

    # -------------------------------------------------
    # Send request
    # -------------------------------------------------

    client.sendall(request.encode("utf-8"))

    # -------------------------------------------------
    # Receive response
    # -------------------------------------------------

    response = client.recv(4096).decode("utf-8")

    print("\nServer response:")
    print(response)

except ConnectionAbortedError:
    print("\nConnection was aborted by the server.")

except ConnectionResetError:
    print("\nConnection was reset by the server.")

except ConnectionRefusedError:
    print("\nCould not connect to the server. Is server.py running?")

except socket.timeout:
    print("\nThe connection timed out.")

finally:

    # -------------------------------------------------
    # Close connection
    # -------------------------------------------------

    client.close()