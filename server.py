import socket
import pickle
import sqlite3
import threading
import time

from datetime import datetime
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor

from cryptography.fernet import Fernet, InvalidToken


# ============================================================
#                 ENCRYPTION CONFIGURATION
# ============================================================

# The same key must be used in client.py

SECRET_KEY = b"nJuxFgnows1o0BjplCFyNYrmSLXjN1w9T86JD2upISY="

cipher = Fernet(SECRET_KEY)


# ============================================================
#                 LOAD MACHINE LEARNING MODEL
# ============================================================

with open("sqli_model.pkl", "rb") as file:
    model = pickle.load(file)

with open("tfidf_vectorizer.pkl", "rb") as file:
    vectorizer = pickle.load(file)


# ============================================================
#                 THREAD POOL CONFIGURATION
# ============================================================

MAX_WORKERS = 10

thread_pool = ThreadPoolExecutor(
    max_workers=MAX_WORKERS
)


# ============================================================
#                 BLOCKED SOURCE PORTS
# ============================================================

blocked_ports = set()

blocked_ports_lock = threading.Lock()


# ============================================================
#                 TOKEN BUCKET CONFIGURATION
# ============================================================

MAX_TOKENS = 3
REFILL_RATE = 1

client_buckets = {}

client_buckets_lock = threading.Lock()


# ============================================================
#                 TOKEN BUCKET RATE LIMITER
# ============================================================

def allow_request(client_ip):
    """
    Check whether a client is allowed to send a request.

    Each client receives:
    - 3 initial tokens
    - 1 new token every second
    """

    current_time = time.time()

    with client_buckets_lock:

        if client_ip not in client_buckets:

            client_buckets[client_ip] = {
                "tokens": MAX_TOKENS,
                "last_refill": current_time
            }

        bucket = client_buckets[client_ip]

        elapsed_time = (
            current_time - bucket["last_refill"]
        )

        new_tokens = elapsed_time * REFILL_RATE

        bucket["tokens"] = min(
            MAX_TOKENS,
            bucket["tokens"] + new_tokens
        )

        bucket["last_refill"] = current_time

        if bucket["tokens"] >= 1:

            bucket["tokens"] -= 1

            return True

        return False


# ============================================================
#                 SEND ENCRYPTED RESPONSE
# ============================================================

def send_encrypted_response(client_socket, response):
    """
    Encrypt and send a response to the client.
    """

    encrypted_response = cipher.encrypt(
        response.encode("utf-8")
    )

    client_socket.sendall(
        encrypted_response
    )


# ============================================================
#                 SAVE SECURITY LOG
# ============================================================

def save_log(
    client_ip,
    client_port,
    request,
    prediction,
    action,
    request_size,
    connection_duration
):
    """
    Save security events into the SQLite database.
    """

    connection = sqlite3.connect(
        "security_logs.db"
    )

    cursor = connection.cursor()

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cursor.execute(
        """
        INSERT INTO security_logs
        (
            timestamp,
            client_ip,
            client_port,
            protocol,
            request,
            request_size,
            connection_duration,
            prediction,
            action
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            timestamp,
            client_ip,
            client_port,
            "TCP",
            request,
            request_size,
            connection_duration,
            prediction,
            action
        )
    )

    connection.commit()
    connection.close()


# ============================================================
#                 HANDLE CLIENT REQUEST
# ============================================================

def handle_client(client_socket, client_address):
    """
    Process one encrypted client request.
    """

    client_ip = client_address[0]
    client_port = client_address[1]

    connection_start = datetime.now()

    # Prevent indefinite waiting
    client_socket.settimeout(3)

    print("\n==============================================")
    print("Client connected!")
    print("Client IP:", client_ip)
    print("Client Port:", client_port)
    print("==============================================")

    try:

        # ----------------------------------------------------
        # Check token bucket rate limit
        # ----------------------------------------------------

        if not allow_request(client_ip):

            print("\nRate limit exceeded!")
            print("Client IP:", client_ip)

            response = (
                "HTTP/1.1 429 Too Many Requests\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Too many requests. Please try again later."
            )

            send_encrypted_response(
                client_socket,
                response
            )

            return

        print("Rate limit check: PASSED")

        # ----------------------------------------------------
        # Check whether the source port is blocked
        # ----------------------------------------------------

        with blocked_ports_lock:

            port_is_blocked = (
                client_port in blocked_ports
            )

        if port_is_blocked:

            print("\nBlocked source port detected!")
            print("Client IP:", client_ip)
            print("Blocked Port:", client_port)

            response = (
                "HTTP/1.1 403 Forbidden\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Source port is blocked."
            )

            send_encrypted_response(
                client_socket,
                response
            )

            return

        # ----------------------------------------------------
        # Receive encrypted request
        # ----------------------------------------------------

        encrypted_data = client_socket.recv(4096)

        if not encrypted_data:

            print("Empty encrypted request received.")

            return

        print("\nEncrypted request received:")
        print(encrypted_data.decode("utf-8"))

        # ----------------------------------------------------
        # Decrypt request
        # ----------------------------------------------------

        try:

            data = cipher.decrypt(
                encrypted_data
            ).decode("utf-8")

        except InvalidToken:

            print("Invalid encryption key or corrupted request.")

            response = (
                "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Invalid encrypted request."
            )

            send_encrypted_response(
                client_socket,
                response
            )

            return

        request_size = len(
            data.encode("utf-8")
        )

        print("\nDecrypted HTTP request:")
        print(data)
        print("Request Size:", request_size, "bytes")

        # ----------------------------------------------------
        # Extract HTTP request information
        # ----------------------------------------------------

        request_lines = data.split("\r\n")

        if (
            not request_lines
            or len(request_lines[0].split()) < 2
        ):

            print("Invalid HTTP request.")

            response = (
                "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Invalid HTTP request."
            )

            send_encrypted_response(
                client_socket,
                response
            )

            return

        request_line = request_lines[0]
        request_parts = request_line.split()

        method = request_parts[0]
        url = request_parts[1]

        username = ""

        # ----------------------------------------------------
        # Process GET request
        # ----------------------------------------------------

        if method == "GET":

            parsed_url = urlparse(url)

            parameters = parse_qs(
                parsed_url.query
            )

            username = parameters.get(
                "username",
                [""]
            )[0]

        # ----------------------------------------------------
        # Process POST request
        # ----------------------------------------------------

        elif method == "POST":

            if "\r\n\r\n" in data:

                body = data.split(
                    "\r\n\r\n",
                    1
                )[1]

                parameters = parse_qs(body)

                username = parameters.get(
                    "username",
                    [""]
                )[0]

        print("HTTP Method:", method)
        print("Extracted username:", username)

        # ----------------------------------------------------
        # MACHINE LEARNING PREDICTION
        # ----------------------------------------------------

        username_tfidf = vectorizer.transform(
            [username]
        )

        prediction = model.predict(
            username_tfidf
        )[0]

        print("Prediction:", prediction)

        # ----------------------------------------------------
        # ALLOW OR BLOCK REQUEST
        # ----------------------------------------------------

        if prediction == "anom":

            response = (
                "HTTP/1.1 403 Forbidden\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n"
                "\r\n"
                "SQL Injection detected! Request BLOCKED."
            )

            action = "BLOCKED"

            # Block the source port
            with blocked_ports_lock:

                blocked_ports.add(
                    client_port
                )

            print("Action:", action)
            print("Source port blocked:", client_port)

        else:

            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Normal request. Request ALLOWED."
            )

            action = "ALLOWED"

            print("Action:", action)

        # ----------------------------------------------------
        # Send encrypted response
        # ----------------------------------------------------

        send_encrypted_response(
            client_socket,
            response
        )

        # ----------------------------------------------------
        # Calculate connection duration
        # ----------------------------------------------------

        connection_end = datetime.now()

        connection_duration = (
            connection_end - connection_start
        ).total_seconds()

        print(
            "Connection Duration:",
            round(connection_duration, 4),
            "seconds"
        )

        # ----------------------------------------------------
        # Save security event
        # ----------------------------------------------------

        save_log(
            client_ip,
            client_port,
            data,
            prediction,
            action,
            request_size,
            connection_duration
        )

        print("Security log saved.")

    except socket.timeout:

        print(
            "Connection timed out for:",
            client_ip,
            client_port
        )

    except Exception as error:

        print(
            "Error while processing client:",
            error
        )

    finally:

        client_socket.close()

        print(
            "Connection closed for:",
            client_ip,
            client_port
        )


# ============================================================
#                 SERVER CONFIGURATION
# ============================================================

HOST = "127.0.0.1"
PORT = 5000

server = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

server.setsockopt(
    socket.SOL_SOCKET,
    socket.SO_REUSEADDR,
    1
)

server.bind(
    (HOST, PORT)
)

server.listen(50)

print("==============================================")
print("       NETWORK SECURITY SERVER")
print("==============================================")
print("Server started successfully!")
print("Host:", HOST)
print("Port:", PORT)
print("Maximum worker threads:", MAX_WORKERS)
print("Maximum tokens per client:", MAX_TOKENS)
print("Token refill rate:", REFILL_RATE, "token/second")
print("Encryption: ENABLED")
print("Waiting for client connections...")
print("Press CTRL + C to stop the server.")


# ============================================================
#                 ACCEPT CLIENT CONNECTIONS
# ============================================================

try:

    while True:

        client_socket, client_address = server.accept()

        print(
            "\nClient accepted:",
            client_address
        )

        thread_pool.submit(
            handle_client,
            client_socket,
            client_address
        )

except KeyboardInterrupt:

    print("\nShutting down server...")

finally:

    server.close()

    thread_pool.shutdown(
        wait=True
    )

    print("Server stopped successfully.")