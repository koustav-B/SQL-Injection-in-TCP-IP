import socket
import pickle
import sqlite3
import threading
import time

from datetime import datetime
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor


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

# Create a fixed-size thread pool
thread_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)


# ============================================================
#                 BLOCKED SOURCE PORTS
# ============================================================

blocked_ports = set()

# Lock for safely accessing blocked_ports
blocked_ports_lock = threading.Lock()


# ============================================================
#                 TOKEN BUCKET CONFIGURATION
# ============================================================

MAX_TOKENS = 3       # Maximum number of tokens in each bucket
REFILL_RATE = 1      # Tokens added per second

# Stores token buckets for each client IP
client_buckets = {}

# Lock for safely accessing client_buckets
client_buckets_lock = threading.Lock()


# ============================================================
#                 TOKEN BUCKET RATE LIMITER
# ============================================================

def allow_request(client_ip):
    """
    Check whether a client is allowed to send a request.

    Each client receives:
    - 5 initial tokens
    - 1 new token every second
    """

    current_time = time.time()

    with client_buckets_lock:

        # Create a bucket for a new client
        if client_ip not in client_buckets:

            client_buckets[client_ip] = {
                "tokens": MAX_TOKENS,
                "last_refill": current_time
            }

        bucket = client_buckets[client_ip]

        # Calculate elapsed time
        elapsed_time = current_time - bucket["last_refill"]

        # Calculate newly generated tokens
        new_tokens = elapsed_time * REFILL_RATE

        # Refill the bucket
        bucket["tokens"] = min(
            MAX_TOKENS,
            bucket["tokens"] + new_tokens
        )

        # Update refill time
        bucket["last_refill"] = current_time

        # Check whether a token is available
        if bucket["tokens"] >= 1:

            bucket["tokens"] -= 1

            return True

        return False


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

    connection = sqlite3.connect("security_logs.db")

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
    Process one client request using a thread-pool worker.
    """

    client_ip = client_address[0]
    client_port = client_address[1]

    connection_start = datetime.now()

    # Set a timeout to prevent indefinite waiting
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

            client_socket.sendall(response.encode("utf-8"))

            return

        print("Rate limit check: PASSED")

        # ----------------------------------------------------
        # Check whether the source port is blocked
        # ----------------------------------------------------

        with blocked_ports_lock:
            port_is_blocked = client_port in blocked_ports

        if port_is_blocked:

            print("\nBlocked source port detected!")
            print("Client IP:", client_ip)
            print("Blocked Port:", client_port)

            return

        # ----------------------------------------------------
        # Receive HTTP request
        # ----------------------------------------------------

        data = client_socket.recv(4096).decode(
            "utf-8",
            errors="replace"
        )

        if not data:

            print("Empty request received.")

            return

        request_size = len(data.encode("utf-8"))

        print("\nReceived HTTP request:")
        print(data)
        print("Request Size:", request_size, "bytes")

        # ----------------------------------------------------
        # Extract HTTP request information
        # ----------------------------------------------------

        request_lines = data.split("\r\n")

        if not request_lines or len(request_lines[0].split()) < 2:

            print("Invalid HTTP request.")

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
                blocked_ports.add(client_port)

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
        # Send HTTP response
        # ----------------------------------------------------

        client_socket.sendall(
            response.encode("utf-8")
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

# Allow immediate reuse of the port after shutdown
server.setsockopt(
    socket.SOL_SOCKET,
    socket.SO_REUSEADDR,
    1
)

server.bind(
    (HOST, PORT)
)

# Connection backlog
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

        # Submit request to the thread pool
        thread_pool.submit(
            handle_client,
            client_socket,
            client_address
        )

except KeyboardInterrupt:

    print("\nShutting down server...")

finally:

    server.close()

    # Wait for worker threads to finish
    thread_pool.shutdown(
        wait=True
    )

    print("Server stopped successfully.")