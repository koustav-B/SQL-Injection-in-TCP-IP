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
#                    SERVER CONFIGURATION
# ============================================================

HOST = "127.0.0.1"
PORT = 5000

MAX_WORKERS = 10

# Maximum TCP request that the server will accept
MAX_REQUEST_SIZE = 8192

# Client connection timeout
CONNECTION_TIMEOUT = 3


# ============================================================
#                    RATE LIMIT CONFIGURATION
# ============================================================

MAX_TOKENS = 3

REFILL_RATE = 1

client_buckets = {}

client_buckets_lock = threading.Lock()


# ============================================================
#                    IP BLOCK CONFIGURATION
# ============================================================

# Temporary IP block duration
BLOCK_DURATION = 60

blocked_ips = {}

blocked_ips_lock = threading.Lock()


# ============================================================
#                    CONNECTION TRACKING
# ============================================================

active_connections = {}

active_connections_lock = threading.Lock()


# ============================================================
#                    SERVER STATISTICS
# ============================================================

statistics = {
    "total_requests": 0,
    "allowed_requests": 0,
    "blocked_requests": 0,
    "rate_limited_requests": 0,
    "invalid_requests": 0,
    "get_requests": 0,
    "post_requests": 0,
    "unique_ips": set()
}

statistics_lock = threading.Lock()


# ============================================================
#                    THREAD POOL
# ============================================================

thread_pool = ThreadPoolExecutor(
    max_workers=MAX_WORKERS
)


# ============================================================
#                    ENCRYPTION CONFIGURATION
# ============================================================

def load_fernet_key():

    """
    Read Fernet key from README.md.
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
            "README.md not found."
        )

    raise ValueError(
        "FERNET_KEY not found in README.md."
    )


SECRET_KEY = load_fernet_key()

cipher = Fernet(
    SECRET_KEY
)


# ============================================================
#                    LOAD ML MODEL
# ============================================================

print("\nLoading machine learning model...")

with open(
    "sqli_model.pkl",
    "rb"
) as file:

    model = pickle.load(file)


print("Loading TF-IDF vectorizer...")

with open(
    "tfidf_vectorizer.pkl",
    "rb"
) as file:

    vectorizer = pickle.load(file)


print("Machine learning model loaded successfully.")


# ============================================================
#                    DATABASE INITIALIZATION
# ============================================================

def initialize_database():

    connection = sqlite3.connect(
        "security_logs.db"
    )

    cursor = connection.cursor()


    # --------------------------------------------------------
    # Security logs
    # --------------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS security_logs
        (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT,

            client_ip TEXT,

            client_port INTEGER,

            protocol TEXT,

            request TEXT,

            request_size INTEGER,

            connection_duration REAL,

            prediction TEXT,

            action TEXT
        )
        """
    )


    # --------------------------------------------------------
    # Persistent blocked IP table
    # --------------------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS blocked_ips
        (
            ip_address TEXT PRIMARY KEY,

            reason TEXT,

            blocked_at TEXT,

            expires_at TEXT
        )
        """
    )


    connection.commit()

    connection.close()


initialize_database()


# ============================================================
#                    LOAD BLOCKED IPS
# ============================================================

def load_blocked_ips():

    """
    Load previously blocked IP addresses from SQLite.
    """

    connection = sqlite3.connect(
        "security_logs.db"
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            ip_address,
            reason,
            expires_at
        FROM blocked_ips
        """
    )

    rows = cursor.fetchall()

    connection.close()


    current_time = time.time()


    with blocked_ips_lock:

        for ip_address, reason, expires_at in rows:

            try:

                expiry_timestamp = float(
                    expires_at
                )

                if expiry_timestamp > current_time:

                    blocked_ips[ip_address] = {
                        "reason": reason,
                        "expires_at": expiry_timestamp
                    }

            except ValueError:

                pass


load_blocked_ips()


# ============================================================
#                    BLOCK IP
# ============================================================

def block_ip(
    client_ip,
    reason
):

    """
    Block an IP address temporarily.

    The block is also saved in SQLite so that
    it survives a server restart.
    """

    current_time = time.time()

    expiry_time = (
        current_time +
        BLOCK_DURATION
    )

    blocked_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with blocked_ips_lock:

        blocked_ips[client_ip] = {
            "reason": reason,
            "expires_at": expiry_time
        }


    connection = sqlite3.connect(
        "security_logs.db"
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT OR REPLACE INTO blocked_ips
        (
            ip_address,
            reason,
            blocked_at,
            expires_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            client_ip,
            reason,
            blocked_time,
            str(expiry_time)
        )
    )

    connection.commit()

    connection.close()


    print(
        "\n=============================================="
    )

    print(
        "IP BLOCKED"
    )

    print(
        "IP:",
        client_ip
    )

    print(
        "Reason:",
        reason
    )

    print(
        "Duration:",
        BLOCK_DURATION,
        "seconds"
    )

    print(
        "=============================================="
    )


# ============================================================
#                    CHECK IP BLOCK
# ============================================================

def is_ip_blocked(
    client_ip
):

    """
    Check whether an IP is currently blocked.
    """

    current_time = time.time()

    with blocked_ips_lock:

        if client_ip not in blocked_ips:

            return False


        block_information = blocked_ips[
            client_ip
        ]

        expiry_time = block_information[
            "expires_at"
        ]


        # ----------------------------------------------------
        # Remove expired block
        # ----------------------------------------------------

        if current_time >= expiry_time:

            del blocked_ips[
                client_ip
            ]

            return False


        return True


# ============================================================
#                    UNBLOCK IP
# ============================================================

def unblock_ip(
    client_ip
):

    """
    Remove an IP address from the blocked list.
    """

    removed = False

    with blocked_ips_lock:

        if client_ip in blocked_ips:

            del blocked_ips[
                client_ip
            ]

            removed = True


    if removed:

        connection = sqlite3.connect(
            "security_logs.db"
        )

        cursor = connection.cursor()

        cursor.execute(
            """
            DELETE FROM blocked_ips
            WHERE ip_address = ?
            """,
            (
                client_ip,
            )
        )

        connection.commit()

        connection.close()


        print(
            "IP unblocked:",
            client_ip
        )

        return True


    print(
        "IP was not blocked:",
        client_ip
    )

    return False


# ============================================================
#                    LIST BLOCKED IPS
# ============================================================

def list_blocked_ips():

    """
    Display currently blocked IP addresses.
    """

    current_time = time.time()

    print(
        "\n=============================================="
    )

    print(
        "              BLOCKED IP ADDRESSES"
    )

    print(
        "=============================================="
    )


    with blocked_ips_lock:

        if not blocked_ips:

            print(
                "No blocked IP addresses."
            )

            return


        for ip_address, information in list(
            blocked_ips.items()
        ):

            remaining = (
                information["expires_at"]
                -
                current_time
            )

            if remaining <= 0:

                del blocked_ips[
                    ip_address
                ]

                continue


            print(
                "IP:",
                ip_address
            )

            print(
                "Reason:",
                information["reason"]
            )

            print(
                "Remaining:",
                round(
                    remaining,
                    1
                ),
                "seconds"
            )

            print(
                "----------------------------------------------"
            )


# ============================================================
#                    TOKEN BUCKET
# ============================================================

def allow_request(
    client_ip
):

    """
    Token bucket rate limiter.

    Each IP receives:

        3 initial tokens
        1 token per second
    """

    current_time = time.time()

    with client_buckets_lock:

        if client_ip not in client_buckets:

            client_buckets[client_ip] = {

                "tokens": MAX_TOKENS,

                "last_refill": current_time
            }


        bucket = client_buckets[
            client_ip
        ]


        elapsed_time = (
            current_time -
            bucket["last_refill"]
        )


        new_tokens = (
            elapsed_time *
            REFILL_RATE
        )


        bucket["tokens"] = min(
            MAX_TOKENS,
            bucket["tokens"] +
            new_tokens
        )


        bucket["last_refill"] = (
            current_time
        )


        if bucket["tokens"] >= 1:

            bucket["tokens"] -= 1

            return True


        return False


# ============================================================
#                    CONNECTION TRACKING
# ============================================================

def add_connection(
    client_ip,
    client_port
):

    """
    Add an active connection.
    """

    connection_id = (
        f"{client_ip}:{client_port}"
    )

    with active_connections_lock:

        active_connections[
            connection_id
        ] = {

            "ip": client_ip,

            "port": client_port,

            "start_time": time.time()
        }


def remove_connection(
    client_ip,
    client_port
):

    """
    Remove a connection after completion.
    """

    connection_id = (
        f"{client_ip}:{client_port}"
    )

    with active_connections_lock:

        active_connections.pop(
            connection_id,
            None
        )


def show_active_connections():

    """
    Display active TCP connections.
    """

    print(
        "\n=============================================="
    )

    print(
        "             ACTIVE CONNECTIONS"
    )

    print(
        "=============================================="
    )


    with active_connections_lock:

        if not active_connections:

            print(
                "No active connections."
            )

            return


        for connection_id, information in (
            active_connections.items()
        ):

            duration = (
                time.time() -
                information["start_time"]
            )

            print(
                "Connection:",
                connection_id
            )

            print(
                "Duration:",
                round(
                    duration,
                    2
                ),
                "seconds"
            )

            print(
                "----------------------------------------------"
            )


# ============================================================
#                    STATISTICS
# ============================================================

def show_statistics():

    """
    Display server network statistics.
    """

    with statistics_lock:

        print(
            "\n=============================================="
        )

        print(
            "             NETWORK STATISTICS"
        )

        print(
            "=============================================="
        )

        print(
            "Total Requests:",
            statistics[
                "total_requests"
            ]
        )

        print(
            "Allowed Requests:",
            statistics[
                "allowed_requests"
            ]
        )

        print(
            "Blocked Requests:",
            statistics[
                "blocked_requests"
            ]
        )

        print(
            "Rate Limited:",
            statistics[
                "rate_limited_requests"
            ]
        )

        print(
            "Invalid Requests:",
            statistics[
                "invalid_requests"
            ]
        )

        print(
            "GET Requests:",
            statistics[
                "get_requests"
            ]
        )

        print(
            "POST Requests:",
            statistics[
                "post_requests"
            ]
        )

        print(
            "Unique IP Addresses:",
            len(
                statistics[
                    "unique_ips"
                ]
            )
        )

        print(
            "=============================================="
        )


# ============================================================
#                    SEND ENCRYPTED RESPONSE
# ============================================================

def send_encrypted_response(
    client_socket,
    response
):

    encrypted_response = cipher.encrypt(
        response.encode("utf-8")
    )

    client_socket.sendall(
        encrypted_response
    )


# ============================================================
#                    SAVE SECURITY LOG
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
#                    HANDLE CLIENT
# ============================================================

def handle_client(
    client_socket,
    client_address
):

    client_ip = client_address[0]

    client_port = client_address[1]

    connection_start = datetime.now()


    client_socket.settimeout(
        CONNECTION_TIMEOUT
    )


    add_connection(
        client_ip,
        client_port
    )


    with statistics_lock:

        statistics[
            "total_requests"
        ] += 1

        statistics[
            "unique_ips"
        ].add(
            client_ip
        )


    print(
        "\n=============================================="
    )

    print(
        "CLIENT CONNECTED"
    )

    print(
        "IP:",
        client_ip
    )

    print(
        "PORT:",
        client_port
    )

    print(
        "=============================================="
    )


    try:

        # ====================================================
        # IP BLOCK CHECK
        # ====================================================

        if is_ip_blocked(
            client_ip
        ):

            print(
                "Blocked IP attempted connection."
            )

            response = (
                "HTTP/1.1 403 Forbidden\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Your IP address is currently blocked."
            )

            send_encrypted_response(
                client_socket,
                response
            )

            with statistics_lock:

                statistics[
                    "blocked_requests"
                ] += 1

            return


        # ====================================================
        # RATE LIMIT CHECK
        # ====================================================

        if not allow_request(
            client_ip
        ):

            print(
                "Rate limit exceeded."
            )

            response = (
                "HTTP/1.1 429 Too Many Requests\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Too many requests. "
                "Please try again later."
            )

            send_encrypted_response(
                client_socket,
                response
            )

            with statistics_lock:

                statistics[
                    "rate_limited_requests"
                ] += 1

            return


        # ====================================================
        # RECEIVE ENCRYPTED DATA
        # ====================================================

        encrypted_data = client_socket.recv(
            MAX_REQUEST_SIZE
        )


        if not encrypted_data:

            print(
                "Empty request received."
            )

            return


        # ====================================================
        # REQUEST SIZE CHECK
        # ====================================================

        if len(encrypted_data) >= MAX_REQUEST_SIZE:

            print(
                "Request size exceeded limit."
            )

            response = (
                "HTTP/1.1 413 Payload Too Large\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Request is too large."
            )

            send_encrypted_response(
                client_socket,
                response
            )

            with statistics_lock:

                statistics[
                    "blocked_requests"
                ] += 1

            return


        print(
            "\nEncrypted request received."
        )


        # ====================================================
        # DECRYPT REQUEST
        # ====================================================

        try:

            data = cipher.decrypt(
                encrypted_data
            ).decode(
                "utf-8"
            )

        except InvalidToken:

            print(
                "Invalid encrypted request."
            )

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

            with statistics_lock:

                statistics[
                    "invalid_requests"
                ] += 1

            return


        request_size = len(
            data.encode(
                "utf-8"
            )
        )


        print(
            "\nDecrypted HTTP request:"
        )

        print(
            data
        )

        print(
            "Request Size:",
            request_size,
            "bytes"
        )


        # ====================================================
        # HTTP REQUEST PARSING
        # ====================================================

        request_lines = data.split(
            "\r\n"
        )


        if (
            not request_lines
            or
            len(
                request_lines[0].split()
            ) < 2
        ):

            print(
                "Invalid HTTP request."
            )

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

            with statistics_lock:

                statistics[
                    "invalid_requests"
                ] += 1

            return


        request_parts = (
            request_lines[0].split()
        )


        method = request_parts[0]

        url = request_parts[1]

        username = ""


        # ====================================================
        # GET
        # ====================================================

        if method == "GET":

            with statistics_lock:

                statistics[
                    "get_requests"
                ] += 1


            parsed_url = urlparse(
                url
            )


            parameters = parse_qs(
                parsed_url.query
            )


            username = parameters.get(
                "username",
                [""]
            )[0]


        # ====================================================
        # POST
        # ====================================================

        elif method == "POST":

            with statistics_lock:

                statistics[
                    "post_requests"
                ] += 1


            if "\r\n\r\n" in data:

                body = data.split(
                    "\r\n\r\n",
                    1
                )[1]


                parameters = parse_qs(
                    body
                )


                username = parameters.get(
                    "username",
                    [""]
                )[0]


        else:

            print(
                "Unsupported HTTP method:",
                method
            )

            response = (
                "HTTP/1.1 405 Method Not Allowed\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n"
                "\r\n"
                "HTTP method not supported."
            )

            send_encrypted_response(
                client_socket,
                response
            )

            return


        print(
            "HTTP Method:",
            method
        )

        print(
            "Username:",
            username
        )


        # ====================================================
        # MACHINE LEARNING DETECTION
        # ====================================================

        username_tfidf = vectorizer.transform(
            [username]
        )


        prediction = model.predict(
            username_tfidf
        )[0]


        print(
            "ML Prediction:",
            prediction
        )


        # ====================================================
        # SQL INJECTION DETECTED
        # ====================================================

        if prediction == "anom":

            print(
                "\n!!! SQL INJECTION DETECTED !!!"
            )


            action = "BLOCKED"


            block_ip(
                client_ip,
                "SQL Injection detected"
            )


            response = (
                "HTTP/1.1 403 Forbidden\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n"
                "\r\n"
                "SQL Injection detected! "
                "Request BLOCKED. "
                "Your IP has been temporarily blocked."
            )


            with statistics_lock:

                statistics[
                    "blocked_requests"
                ] += 1


        # ====================================================
        # NORMAL REQUEST
        # ====================================================

        else:

            print(
                "\nNormal request detected."
            )


            action = "ALLOWED"


            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Normal request. "
                "Request ALLOWED."
            )


            with statistics_lock:

                statistics[
                    "allowed_requests"
                ] += 1


        # ====================================================
        # SEND RESPONSE
        # ====================================================

        send_encrypted_response(
            client_socket,
            response
        )


        # ====================================================
        # CONNECTION DURATION
        # ====================================================

        connection_end = datetime.now()


        connection_duration = (
            connection_end -
            connection_start
        ).total_seconds()


        print(
            "Connection Duration:",
            round(
                connection_duration,
                4
            ),
            "seconds"
        )


        # ====================================================
        # SECURITY LOG
        # ====================================================

        save_log(
            client_ip,
            client_port,
            data,
            prediction,
            action,
            request_size,
            connection_duration
        )


        print(
            "Security log saved."
        )


    except socket.timeout:

        print(
            "\nConnection timeout:"
        )

        print(
            client_ip,
            client_port
        )


    except ConnectionResetError:

        print(
            "\nConnection reset by client."
        )


    except Exception as error:

        print(
            "\nError:",
            error
        )


    finally:

        remove_connection(
            client_ip,
            client_port
        )


        client_socket.close()


        print(
            "Connection closed:",
            client_ip,
            client_port
        )


# ============================================================
#                    ADMIN CONSOLE
# ============================================================

def admin_console():

    """
    Server administrator console.

    Commands:

        stats
        blocked
        unblock <IP>
        connections
        help
        exit
    """

    while True:

        try:

            command = input(
                "\nADMIN> "
            ).strip()


            if command == "stats":

                show_statistics()


            elif command == "blocked":

                list_blocked_ips()


            elif command.startswith(
                "unblock "
            ):

                ip_address = command.split(
                    " ",
                    1
                )[1].strip()


                unblock_ip(
                    ip_address
                )


            elif command == "connections":

                show_active_connections()


            elif command == "help":

                print(
                    "\nAvailable commands:"
                )

                print(
                    "stats"
                )

                print(
                    "blocked"
                )

                print(
                    "unblock <IP>"
                )

                print(
                    "connections"
                )

                print(
                    "help"
                )

                print(
                    "exit"
                )


            elif command == "exit":

                print(
                    "Stopping server..."
                )

                break


            elif command == "":

                continue


            else:

                print(
                    "Unknown command."
                )

                print(
                    "Type 'help' for commands."
                )


        except EOFError:

            break


# ============================================================
#                    CREATE TCP SERVER
# ============================================================

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
    (
        HOST,
        PORT
    )
)


server.listen(
    50
)


# ============================================================
#                    SERVER STARTUP
# ============================================================

print(
    "\n=============================================="
)

print(
    "          NETWORK SECURITY SERVER"
)

print(
    "=============================================="
)

print(
    "Server started successfully!"
)

print(
    "Host:",
    HOST
)

print(
    "Port:",
    PORT
)

print(
    "Protocol: TCP"
)

print(
    "Thread Pool:",
    MAX_WORKERS
)

print(
    "Rate Limit:",
    MAX_TOKENS,
    "tokens"
)

print(
    "Refill Rate:",
    REFILL_RATE,
    "token/second"
)

print(
    "Maximum Request Size:",
    MAX_REQUEST_SIZE,
    "bytes"
)

print(
    "Connection Timeout:",
    CONNECTION_TIMEOUT,
    "seconds"
)

print(
    "IP Block Duration:",
    BLOCK_DURATION,
    "seconds"
)

print(
    "Encryption: ENABLED"
)

print(
    "ML SQL Injection Detection: ENABLED"
)

print(
    "Persistent IP Blocking: ENABLED"
)

print(
    "Connection Tracking: ENABLED"
)

print(
    "Traffic Statistics: ENABLED"
)

print(
    "Admin Console: ENABLED"
)

print(
    "=============================================="
)

print(
    "Waiting for client connections..."
)

print(
    "Type 'help' for administrator commands."
)

print(
    "=============================================="
)


# ============================================================
#                    START ADMIN CONSOLE
# ============================================================

admin_thread = threading.Thread(
    target=admin_console,
    daemon=True
)

admin_thread.start()


# ============================================================
#                    ACCEPT CLIENTS
# ============================================================

try:

    while True:

        client_socket, client_address = (
            server.accept()
        )


        print(
            "\nNew connection:",
            client_address
        )


        thread_pool.submit(
            handle_client,
            client_socket,
            client_address
        )


except KeyboardInterrupt:

    print(
        "\n\nCTRL+C detected."
    )


finally:

    print(
        "Shutting down server..."
    )


    server.close()


    thread_pool.shutdown(
        wait=True
    )


    print(
        "Server stopped successfully."
    )