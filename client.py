import socket
from urllib.parse import quote
from cryptography.fernet import Fernet

# -------------------------------------------------
# Server configuration
# -------------------------------------------------

HOST = "127.0.0.1"
PORT = 5000

# -------------------------------------------------
# Encryption configuration
# -------------------------------------------------

# The same key must be used in server.py

SECRET_KEY = b"nJuxFgnows1o0BjplCFyNYrmSLXjN1w9T86JD2upISY="

cipher = Fernet(SECRET_KEY)

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
# Display original request
# -------------------------------------------------

print("\nOriginal HTTP request:")
print(request)

# -------------------------------------------------
# Encrypt HTTP request
# -------------------------------------------------

encrypted_request = cipher.encrypt(
    request.encode("utf-8")
)

print("Encrypted request:")
print(encrypted_request.decode("utf-8"))

# -------------------------------------------------
# Create TCP socket
# -------------------------------------------------

client = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

client.settimeout(5)

try:

    # -------------------------------------------------
    # Connect to server
    # -------------------------------------------------

    client.connect((HOST, PORT))

    # -------------------------------------------------
    # Send encrypted request
    # -------------------------------------------------

    client.sendall(encrypted_request)

    print("\nEncrypted request sent to server.")

    # -------------------------------------------------
    # Receive encrypted response
    # -------------------------------------------------

    encrypted_response = client.recv(4096)

    if not encrypted_response:

        print("\nServer closed the connection without a response.")

    else:

        print("\nEncrypted server response:")
        print(encrypted_response.decode("utf-8"))

        # -------------------------------------------------
        # Decrypt server response
        # -------------------------------------------------

        response = cipher.decrypt(
            encrypted_response
        ).decode("utf-8")

        # -------------------------------------------------
        # Display decrypted response
        # -------------------------------------------------

        print("\nDecrypted server response:")
        print(response)

except ConnectionAbortedError:

    print("\nConnection was aborted by the server.")

except ConnectionResetError:

    print("\nConnection was reset by the server.")

except ConnectionRefusedError:

    print("\nCould not connect to the server. Is server.py running?")

except socket.timeout:

    print("\nThe connection timed out.")

except Exception as error:

    print(f"\nEncryption or communication error: {error}")

finally:

    # -------------------------------------------------
    # Close connection
    # -------------------------------------------------

    client.close()

    print("\nConnection closed.")