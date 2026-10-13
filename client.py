
import socket
from urllib.parse import quote

from cryptography.fernet import Fernet


# ============================================================
#                 SERVER CONFIGURATION
# ============================================================

HOST = "127.0.0.1"

PORT = 5000


# ============================================================
#                 ENCRYPTION CONFIGURATION
# ============================================================

def load_fernet_key():
    """
    Read the Fernet encryption key from README.md.
    """

    try:

        with open(
            "README.md",
            "r",
            encoding="utf-8"
        ) as file:

            for line in file:

                line = line.strip()

                if line.startswith("FERNET_KEY="):

                    key = line.split(
                        "=",
                        1
                    )[1].strip()

                    return key.encode("utf-8")

    except FileNotFoundError:

        raise FileNotFoundError(
            "README.md not found. "
            "Please make sure README.md is in the same "
            "folder as client.py."
        )

    raise ValueError(
        "FERNET_KEY not found in README.md."
    )


# Load the same encryption key used by server.py
SECRET_KEY = load_fernet_key()

# Create Fernet encryption object
cipher = Fernet(SECRET_KEY)


# ============================================================
#                 CHOOSE HTTP METHOD
# ============================================================

method = input(
    "Enter request method (GET/POST): "
).upper()


# ============================================================
#                 GET USERNAME
# ============================================================

username = input(
    "Enter username: "
)


# ============================================================
#                 URL ENCODE USERNAME
# ============================================================

encoded_username = quote(
    username
)


# ============================================================
#                 CREATE HTTP REQUEST
# ============================================================

if method == "GET":

    request = (
        f"GET /login?username={encoded_username} HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Connection: close\r\n"
        "\r\n"
    )


elif method == "POST":

    body = (
        f"username={encoded_username}"
    )

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

    print(
        "Invalid request method!"
    )

    exit()


# ============================================================
#                 DISPLAY ORIGINAL REQUEST
# ============================================================

print(
    "\nOriginal HTTP request:"
)

print(
    request
)


# ============================================================
#                 ENCRYPT HTTP REQUEST
# ============================================================

encrypted_request = cipher.encrypt(
    request.encode("utf-8")
)


print(
    "Encrypted request:"
)

print(
    encrypted_request.decode("utf-8")
)


# ============================================================
#                 CREATE TCP SOCKET
# ============================================================

client = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)


# Prevent indefinite waiting
client.settimeout(5)


try:

    # --------------------------------------------------------
    # Connect to server
    # --------------------------------------------------------

    client.connect(
        (HOST, PORT)
    )


    # --------------------------------------------------------
    # Send encrypted request
    # --------------------------------------------------------

    client.sendall(
        encrypted_request
    )


    print(
        "\nEncrypted request sent to server."
    )


    # --------------------------------------------------------
    # Receive encrypted response
    # --------------------------------------------------------

    encrypted_response = client.recv(
        4096
    )


    if not encrypted_response:

        print(
            "\nServer closed the connection "
            "without a response."
        )


    else:

        print(
            "\nEncrypted server response:"
        )

        print(
            encrypted_response.decode(
                "utf-8"
            )
        )


        # ----------------------------------------------------
        # Decrypt server response
        # ----------------------------------------------------

        response = cipher.decrypt(
            encrypted_response
        ).decode(
            "utf-8"
        )


        # ----------------------------------------------------
        # Display decrypted response
        # ----------------------------------------------------

        print(
            "\nDecrypted server response:"
        )

        print(
            response
        )


# ============================================================
#                 CONNECTION ERROR HANDLING
# ============================================================

except ConnectionAbortedError:

    print(
        "\nConnection was aborted by the server."
    )


except ConnectionResetError:

    print(
        "\nConnection was reset by the server."
    )


except ConnectionRefusedError:

    print(
        "\nCould not connect to the server. "
        "Is server.py running?"
    )


except socket.timeout:

    print(
        "\nThe connection timed out."
    )


except Exception as error:

    print(
        f"\nEncryption or communication error: {error}"
    )


finally:

    # --------------------------------------------------------
    # Close connection
    # --------------------------------------------------------

    client.close()

    print(
        "\nConnection closed."
    )